defmodule LakehouseMatrix.LegacySyncTest do
  use LakehouseMatrix.DataCase, async: false
  alias LakehouseMatrix.{ClientRooms, ClientStore, Cursor, Fixtures, Identity, LegacySync, Matrix}
  alias LakehouseMatrix.Protocol.Graph

  setup do
    keys = [:native_event_graph, :signing_key, :signing_key_id]
    old = Map.new(keys, &{&1, Application.get_env(:lakehouse_matrix, &1)})
    Application.put_env(:lakehouse_matrix, :native_event_graph, true)

    Application.put_env(
      :lakehouse_matrix,
      :signing_key,
      Base.encode64(<<0::256>>, padding: false)
    )

    Application.put_env(:lakehouse_matrix, :signing_key_id, "ed25519:test")

    on_exit(fn ->
      for {key, value} <- old do
        if is_nil(value),
          do: Application.delete_env(:lakehouse_matrix, key),
          else: Application.put_env(:lakehouse_matrix, key, value)
      end
    end)

    alice = Fixtures.user_fixture("alice")
    bob = Fixtures.user_fixture("bob")
    outsider = Fixtures.user_fixture("outsider")
    {:ok, %{"room_id" => ref}} = ClientRooms.create(alice.id, %{"preset" => "public_chat"})
    {:ok, local} = Identity.parse_room_id(ref)

    %{
      alice: alice,
      bob: bob,
      outsider: outsider,
      ref: ref,
      local: local,
      user: Identity.user_id(alice.username)
    }
  end

  test "initial snapshots include bounded current state, private data and reusable stream/history tokens",
       c do
    {:ok, _} = ClientStore.put_data(c.alice.id, "", "test.global", %{"private" => true})
    {:ok, _} = ClientStore.put_data(c.alice.id, c.ref, "test.room", %{"private" => true})

    for body <- ["first", "second", "third"],
        do: Graph.send(c.local, c.user, "m.room.message", %{"body" => body})

    assert {:ok, initial} = LegacySync.initial(c.alice.id, "D", %{"limit" => "2"})
    assert [%{"room_id" => ref, "membership" => "join"} = room] = initial["rooms"]
    assert ref == c.ref
    assert Enum.map(room["messages"]["chunk"], & &1["content"]["body"]) == ["second", "third"]
    assert Enum.any?(room["state"], &(&1["type"] == "m.room.create"))
    assert room["account_data"] == [%{"type" => "test.room", "content" => %{"private" => true}}]
    assert Enum.any?(initial["account_data"], &(&1["type"] == "test.global"))

    assert {:ok, page} =
             LakehouseMatrix.ClientSync.history(c.alice.id, "D", c.local, %{
               "from" => room["messages"]["start"],
               "dir" => "b"
             })

    assert Enum.any?(page["chunk"], &(&1["content"]["body"] == "first"))
    {:ok, event} = Graph.send(c.local, c.user, "m.room.message", %{"body" => "next"})

    assert {:ok, stream} =
             LegacySync.stream(c.alice.id, "D", %{"from" => initial["end"], "timeout" => 0})

    assert Enum.any?(
             stream["chunk"],
             &(&1["event_id"] == event["event_id"] and &1["room_id"] == c.ref)
           )

    assert {:error, :invalid_cursor} =
             LegacySync.stream(c.bob.id, "D", %{"from" => stream["end"], "timeout" => 0})

    assert {:error, :invalid_param} =
             LegacySync.initial(c.alice.id, "D", %{"archived" => "maybe"})
  end

  test "peeking permits world-readable rooms, conceals private events and rechecks visibility on every stream request",
       c do
    {:ok, secret} = Graph.send(c.local, c.user, "m.room.message", %{"body" => "private"})
    assert {:error, :forbidden} = LegacySync.room(c.outsider.id, "O", c.ref, %{})
    assert {:error, :not_found} = LegacySync.event(c.outsider.id, secret["event_id"])

    assert {:ok, _} =
             ClientRooms.put_state(c.alice.id, c.ref, "m.room.history_visibility", "", %{
               "history_visibility" => "world_readable"
             })

    {:ok, public} = Graph.send(c.local, c.user, "m.room.message", %{"body" => "public"})
    assert {:ok, preview} = LegacySync.room(c.outsider.id, "O", c.ref, %{})
    refute Map.has_key?(preview, "membership")
    assert Enum.any?(preview["messages"]["chunk"], &(&1["event_id"] == public["event_id"]))
    refute Enum.any?(preview["messages"]["chunk"], &(&1["event_id"] == secret["event_id"]))

    assert {:ok, stream} =
             LegacySync.stream(c.outsider.id, "O", %{
               "from" => preview["messages"]["end"],
               "room_id" => c.ref,
               "timeout" => 0
             })

    assert stream["chunk"] == []

    assert {:ok, _} =
             ClientRooms.put_state(c.alice.id, c.ref, "m.room.history_visibility", "", %{
               "history_visibility" => "shared"
             })

    assert {:error, :forbidden} =
             LegacySync.stream(c.outsider.id, "O", %{
               "from" => stream["end"],
               "room_id" => c.ref,
               "timeout" => 0
             })
  end

  test "archived snapshots stop at leave and invitations contain stripped state only", c do
    {:ok, _} = Matrix.join_room(c.bob.id, c.ref)
    {:ok, old} = Graph.send(c.local, c.user, "m.room.message", %{"body" => "before leave"})
    {:ok, _} = Matrix.leave_room(c.bob.id, c.ref)
    {:ok, later} = Graph.send(c.local, c.user, "m.room.message", %{"body" => "after leave"})
    assert {:ok, %{"rooms" => []}} = LegacySync.initial(c.bob.id, "B", %{})
    assert {:ok, %{"rooms" => [left]}} = LegacySync.initial(c.bob.id, "B", %{"archived" => true})
    assert left["membership"] == "leave"
    assert Enum.any?(left["messages"]["chunk"], &(&1["event_id"] == old["event_id"]))
    refute Enum.any?(left["messages"]["chunk"], &(&1["event_id"] == later["event_id"]))
    {:ok, _} = Matrix.invite(c.alice.id, c.ref, c.outsider.username)
    assert {:ok, %{"rooms" => [invite]}} = LegacySync.initial(c.outsider.id, "O", %{})
    assert invite["membership"] == "invite"
    refute Map.has_key?(invite, "messages")
    refute Enum.any?(invite["state"], &(&1["type"] == "m.room.message"))

    # A River discussion's parent policy still applies to archived history.
    {:ok, %{"room_id" => parent_ref}} = ClientRooms.create(c.alice.id, %{})
    {:ok, parent} = Identity.parse_room_id(parent_ref)
    {:ok, post} = Graph.send(parent, c.user, "cool.gravitas.river.post.v1", %{"body" => "Post"})

    Repo.insert!(%LakehouseMatrix.Schema.RiverPublication{
      id: post["event_id"],
      space_id: parent,
      author_id: c.alice.id,
      thread_id: c.local,
      anchor_id: old["event_id"]
    })

    assert {:ok, %{"rooms" => []}} = LegacySync.initial(c.bob.id, "B", %{"archived" => true})
  end

  test "bursts paginate without dropping events and state changes survive their older timeline position",
       c do
    {:ok, _} = Matrix.join_room(c.bob.id, c.ref)

    {:ok, state_event} =
      Graph.send(c.local, c.user, "m.room.name", %{"name" => "Resolved name"}, "")

    state_from = Cursor.encode("sync", c.bob.id, "B", ClientStore.position())

    Repo.insert_all("matrix_state_changes", [
      %{
        local_room_id: ClientStore.dump_id(c.local),
        type: "m.room.name",
        state_key: "",
        event_id: state_event["event_id"]
      }
    ])

    assert {:ok, state_stream} =
             LegacySync.stream(c.bob.id, "B", %{"from" => state_from, "timeout" => 0})

    assert Enum.any?(state_stream["chunk"], &(&1["event_id"] == state_event["event_id"]))
    from = Cursor.encode("sync", c.bob.id, "B", ClientStore.position())
    now = DateTime.utc_now()
    # A large legacy room exercises stream paging without spending the test on
    # PDU signing; both room stores share the same client stream.
    Application.put_env(:lakehouse_matrix, :native_event_graph, false)
    {:ok, %{"room_id" => legacy_ref}} = ClientRooms.create(c.bob.id, %{"name" => "Burst"})
    Application.put_env(:lakehouse_matrix, :native_event_graph, true)
    {:ok, legacy_id} = Identity.parse_room_id(legacy_ref)
    principal = c.bob.id

    entries =
      for i <- 1..1100,
          do: %{
            id: Ecto.UUID.bingenerate(),
            room_id: ClientStore.dump_id(legacy_id),
            event_id: "$burst#{i}",
            type: "m.room.message",
            content: %{"body" => "#{i}"},
            sender: Identity.user_id(c.bob.username),
            principal_id: ClientStore.dump_id(principal),
            origin_server_ts: i,
            inserted_at: now
          }

    Repo.insert_all("room_events", entries)
    assert {:ok, first} = LegacySync.stream(principal, "B", %{"from" => from, "timeout" => 0})

    assert {:ok, second} =
             LegacySync.stream(principal, "B", %{"from" => first["end"], "timeout" => 0})

    ids =
      (first["chunk"] ++ second["chunk"])
      |> Enum.map(& &1["event_id"])
      |> Enum.filter(&(is_binary(&1) and String.starts_with?(&1, "$burst")))

    assert length(ids) == 1100
    assert length(Enum.uniq(ids)) == 1100
  end
end
