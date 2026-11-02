defmodule LakehouseMatrix.Protocol.RoomVersionsTest do
  use LakehouseMatrix.DataCase, async: false

  alias LakehouseMatrix.{
    ClientRooms,
    ClientStore,
    Fixtures,
    Identity,
    RoomVersions,
    RoomVersionWorker
  }

  alias LakehouseMatrix.Federation.RoomAccess
  alias LakehouseMatrix.Protocol.{Graph, Event}

  setup do
    keys = [
      :native_event_graph,
      :automatic_room_versions,
      :room_version_fetcher,
      :signing_key,
      :signing_key_id
    ]

    old = Map.new(keys, &{&1, Application.get_env(:lakehouse_matrix, &1)})
    Application.put_env(:lakehouse_matrix, :native_event_graph, true)
    Application.put_env(:lakehouse_matrix, :automatic_room_versions, true)

    Application.put_env(
      :lakehouse_matrix,
      :signing_key,
      Base.encode64(<<0::256>>, padding: false)
    )

    Application.put_env(:lakehouse_matrix, :signing_key_id, "ed25519:test")

    Application.put_env(:lakehouse_matrix, :room_version_fetcher, fn _ ->
      {:error, :unavailable}
    end)

    on_exit(fn ->
      for {key, value} <- old do
        if is_nil(value),
          do: Application.delete_env(:lakehouse_matrix, key),
          else: Application.put_env(:lakehouse_matrix, key, value)
      end
    end)

    %{alice: Fixtures.user_fixture("alice"), bob: Fixtures.user_fixture("bob")}
  end

  defp create(ctx, version, peers \\ ["@peer:remote.test"]) do
    {:ok, %{"room_id" => room}} =
      ClientRooms.create(ctx.alice.id, %{
        "room_version" => version,
        "invite" => peers,
        "initial_state" => [
          %{
            "type" => "m.room.encryption",
            "state_key" => "",
            "content" => %{"algorithm" => "m.megolm.v1.aes-sha2"}
          }
        ]
      })

    {:ok, _} = ClientStore.put_data(ctx.alice.id, "", "m.direct", Map.new(peers, &{&1, [room]}))
    room
  end

  test "new rooms choose the highest common locally implemented stable version", ctx do
    :ok = RoomVersions.observe("remote.test", ["9", "10", "11", "org.example.99"])

    {:ok, %{"room_id" => room}} =
      ClientRooms.create(ctx.alice.id, %{"invite" => ["@peer:remote.test"]})

    assert Graph.room_by_id(room).version == "11"
    assert RoomVersions.preferred([]) == "12"
    assert RoomVersions.best([["9", "13"], ["9", "11", "12"]]) == "9"
  end

  test "every participating server constrains the version; departed servers do not", ctx do
    RoomVersions.observe("remote.test", Event.versions())
    RoomVersions.observe("older.test", ["9"])
    room = create(ctx, "11", ["@peer:remote.test", "@old:older.test"])

    assert {:ok, %{status: "upgraded", version: "9", replacement_room: target}} =
             RoomVersionWorker.reconcile(room)

    assert Graph.room_by_id(target).version == "9"
  end

  test "a server upgrade triggers one linked replacement and preserves encryption, invitations, history and direct routing",
       ctx do
    RoomVersions.observe("remote.test", ["9"])
    room = create(ctx, "9")

    {:ok, sent} =
      ClientRooms.send(ctx.alice.id, "A", room, "m.room.message", "history", %{
        "msgtype" => "m.text",
        "body" => "keep this"
      })

    before = Graph.event(sent["event_id"]).pdu
    assert {:ok, %{status: "current", version: "9"}} = RoomVersionWorker.reconcile(room)
    RoomVersions.observe("remote.test", Event.versions())

    assert {:ok, %{status: "upgraded", version: "12", replacement_room: target}} =
             RoomVersionWorker.reconcile(room)

    state = RoomAccess.state(Graph.room_by_id(target))
    assert state[{"m.room.create", ""}]["content"]["predecessor"]["room_id"] == room
    assert state[{"m.room.encryption", ""}]["content"]["algorithm"] == "m.megolm.v1.aes-sha2"
    assert state[{"m.room.member", "@peer:remote.test"}]["content"]["membership"] == "invite"
    assert ClientStore.get_data(ctx.alice.id, "", "m.direct")["@peer:remote.test"] == [target]
    assert Graph.event(sent["event_id"]).pdu == before
    assert {:ok, %{status: "replaced"}} = RoomVersionWorker.reconcile(room)
    assert {:ok, %{status: "current"}} = RoomVersionWorker.reconcile(target)
  end

  test "unknown, expired, invalid and disjoint capabilities never trigger a replacement", ctx do
    room = create(ctx, "9")
    assert {:error, :waiting_for_capabilities} = RoomVersionWorker.reconcile(room)
    RoomVersions.observe("remote.test", ["11"])

    Repo.query!("UPDATE matrix_peer_room_versions SET confirmed_at = $1", [
      DateTime.add(ClientStore.now(), -4000, :second)
    ])

    assert {:error, :waiting_for_capabilities} = RoomVersionWorker.reconcile(room)
    RoomVersions.observe("remote.test", ["not-implemented"])
    assert {:error, :no_common_version} = RoomVersionWorker.reconcile(room)
    assert {:error, :invalid_capabilities} = RoomVersions.observe("remote.test", [nil])
    refute RoomAccess.state(Graph.room_by_id(room))[{"m.room.tombstone", ""}]
  end

  test "transient refresh failure retains the last confirmed supported versions" do
    RoomVersions.observe("remote.test", ["9", "11"])
    assert {:error, :unavailable} = RoomVersions.refresh("remote.test", true)
    assert {:ok, "11"} = RoomVersions.common(["remote.test"])
    assert RoomVersions.snapshot("remote.test").versions == ["9", "11"]
  end

  test "capability checks run outside the global room transaction and refresh updated peers",
       ctx do
    Application.put_env(:lakehouse_matrix, :room_version_fetcher, fn "remote.test" ->
      refute Repo.in_transaction?()
      {:ok, ["9", "11"]}
    end)

    room = create(ctx, "9")
    assert {:ok, %{status: "upgraded", version: "11"}} = RoomVersionWorker.reconcile(room)
  end

  test "a downgrade refuses room features absent from the target version", ctx do
    room = create(ctx, "12")

    {:ok, _} =
      ClientRooms.put_state(ctx.alice.id, room, "m.room.join_rules", "", %{
        "join_rule" => "knock_restricted",
        "allow" => []
      })

    RoomVersions.observe("remote.test", ["9"])
    assert {:error, :unsupported_room_features} = RoomVersionWorker.reconcile(room)
    refute RoomAccess.state(Graph.room_by_id(room))[{"m.room.tombstone", ""}]
  end

  test "worker persists status and due time instead of repeatedly replacing a room", ctx do
    RoomVersions.observe("remote.test", ["9", "11"])
    room = create(ctx, "9")
    RoomVersionWorker.run_once()
    id = Graph.room_by_id(room).local_room_id

    assert Repo.one(
             from c in "matrix_room_version_checks",
               where: c.room_id == type(^id, :binary_id),
               select: c.status
           ) == "upgraded"

    count = Repo.aggregate(LakehouseMatrix.Schema.ProtocolRoom, :count)
    RoomVersionWorker.run_once()
    assert Repo.aggregate(LakehouseMatrix.Schema.ProtocolRoom, :count) == count
  end

  test "confirmed disjoint support rejects a new incompatible conversation", ctx do
    RoomVersions.observe("remote.test", ["1", "2"])

    assert {:error, :unsupported_room_version} =
             ClientRooms.create(ctx.alice.id, %{"invite" => ["@peer:remote.test"]})
  end

  test "fresh stable capabilities take priority over a subset offered in a join" do
    Application.put_env(:lakehouse_matrix, :room_version_fetcher, fn _ ->
      {:ok, ["9", "11", "12"]}
    end)

    :ok = RoomVersions.refresh("remote.test", true)
    :ok = RoomVersions.observe("remote.test", ["9"])
    assert {:ok, "12"} = RoomVersions.common(["remote.test"])
  end

  test "ordinary members cannot trigger an unauthorized automatic upgrade", ctx do
    room = create(ctx, "9", [Identity.user_id("bob"), "@peer:remote.test"])
    {:ok, _} = LakehouseMatrix.Matrix.join_room(ctx.bob.id, room)
    {:ok, _} = LakehouseMatrix.Matrix.leave_room(ctx.alice.id, room)
    RoomVersions.observe("remote.test", ["9", "11", "12"])
    assert {:error, :no_authorized_local_member} = RoomVersionWorker.reconcile(room)
    refute RoomAccess.state(Graph.room_by_id(room))[{"m.room.tombstone", ""}]
  end

  test "ban state and River group metadata survive an automatic replacement", ctx do
    charlie = Fixtures.user_fixture("charlie")
    room = create(ctx, "9", [Identity.user_id("charlie"), "@peer:remote.test"])

    {:ok, _} =
      ClientRooms.put_state(
        ctx.alice.id,
        room,
        "m.room.member",
        Identity.user_id(charlie.username),
        %{"membership" => "ban", "reason" => "blocked"}
      )

    {:ok, _} =
      ClientRooms.put_state(ctx.alice.id, room, "cool.gravitas.river.group.v1", "", %{
        "kind" => "channel",
        "channel_kind" => "chat"
      })

    RoomVersions.observe("remote.test", ["9", "11"])
    assert {:ok, %{replacement_room: target}} = RoomVersionWorker.reconcile(room)
    state = RoomAccess.state(Graph.room_by_id(target))

    assert state[{"m.room.member", Identity.user_id(charlie.username)}]["content"]["membership"] ==
             "ban"

    assert state[{"cool.gravitas.river.group.v1", ""}]["content"]["kind"] == "channel"
  end

  test "capability advertisements reflect enabled local support and retain future peer versions" do
    RoomVersions.observe("remote.test", ["9", "11", "12", "13"])
    assert "13" in RoomVersions.snapshot("remote.test").versions
    assert {:ok, "12"} = RoomVersions.common(["remote.test"])
    Application.put_env(:lakehouse_matrix, :native_event_graph, false)
    assert RoomVersions.available() == %{"11" => "stable"}
    assert RoomVersions.best([["9", "11", "12"]]) == "11"
  end
end
