defmodule LakehouseMatrix.Federation.DeliveryTest do
  use LakehouseMatrix.DataCase, async: false
  alias LakehouseMatrix.{ClientStore, Fixtures, Identity, Rooms}
  alias LakehouseMatrix.Federation.{Edus, Inbox, Keyring, Outbox, Signing, Transactions}
  alias LakehouseMatrix.Protocol.{Event, Graph}
  @local <<0::256>>
  @remote <<1::256>>
  @bob "@bob:remote.org"

  setup do
    settings = [:homeserver_domain, :signing_key, :signing_key_id]
    old = Map.new(settings, &{&1, Application.get_env(:lakehouse_matrix, &1)})
    Application.put_env(:lakehouse_matrix, :homeserver_domain, "example.org")
    Application.put_env(:lakehouse_matrix, :signing_key, Base.encode64(@local, padding: false))
    Application.put_env(:lakehouse_matrix, :signing_key_id, "ed25519:test")

    on_exit(fn ->
      for {k, v} <- old do
        if is_nil(v),
          do: Application.delete_env(:lakehouse_matrix, k),
          else: Application.put_env(:lakehouse_matrix, k, v)
      end
    end)

    alice = Fixtures.user_fixture("alice")
    {:ok, _} = ClientStore.login("alice", "password123", %{"device_id" => "A"})
    user = Identity.user_id(alice.username)
    {:ok, room} = Rooms.create_room_record(%{name: "Delivery"})
    {:ok, _} = Graph.create(room.id, user)
    {:ok, _} = Graph.send(room.id, user, "m.room.member", %{"membership" => "join"}, user)
    {:ok, _} = Graph.send(room.id, user, "m.room.join_rules", %{"join_rule" => "public"}, "")

    keys =
      Signing.sign(
        %{
          "server_name" => "remote.org",
          "valid_until_ts" => System.system_time(:millisecond) + 60_000,
          "verify_keys" => %{
            "ed25519:test" => %{
              "key" => Base.encode64(Signing.public_key(@remote), padding: false)
            }
          },
          "old_verify_keys" => %{}
        },
        @remote,
        "ed25519:test",
        "remote.org"
      )

    :ok = Keyring.remember("remote.org", keys)
    join = remote(room.id, "m.room.member", %{"membership" => "join"}, @bob)
    {:ok, _} = Graph.receive_pdu(room.id, join)
    %{room: room, alice: alice, user: user}
  end

  defp remote(room, type, content, key \\ nil) do
    Graph.template(Graph.room(room), Graph.load_graph(room), @bob, type, content, key)
    |> Event.sign("12", @remote, "ed25519:test", "remote.org")
  end

  defp transaction(pdus, edus \\ []),
    do: %{
      "origin" => "remote.org",
      "origin_server_ts" => 1_000_000,
      "pdus" => pdus,
      "edus" => edus
    }

  test "reverse-order PDU batches resolve dependencies and transaction replays have no extra effects",
       ctx do
    first = remote(ctx.room.id, "m.room.message", %{"body" => "first"})

    second =
      remote(ctx.room.id, "m.room.message", %{"body" => "second"})
      |> Map.put("prev_events", [Event.id(first, "12")])
      |> Map.put("depth", first["depth"] + 1)
      |> Event.sign("12", @remote, "ed25519:test", "remote.org")

    assert {:ok, response} =
             Transactions.receive("remote.org", "reverse", transaction([second, first]))

    assert response["pdus"][Event.id(first, "12")] == %{}
    assert response["pdus"][Event.id(second, "12")] == %{}
    third = remote(ctx.room.id, "m.room.message", %{"body" => "must not replay"})
    assert {:ok, ^response} = Transactions.receive("remote.org", "reverse", transaction([third]))
    refute Graph.event(Event.id(third, "12"))
    assert Repo.aggregate("matrix_federation_inbox", :count) == 0
  end

  test "one unauthorized PDU cannot roll back other PDUs and missing events are durably queued",
       ctx do
    bad = remote(ctx.room.id, "m.room.member", %{"membership" => "ban"}, ctx.user)
    good = remote(ctx.room.id, "m.room.message", %{"body" => "accepted"})
    assert {:ok, response} = Transactions.receive("remote.org", "mixed", transaction([bad, good]))
    assert response["pdus"][Event.id(bad, "12")]["error"]
    assert response["pdus"][Event.id(good, "12")] == %{}

    missing =
      remote(ctx.room.id, "m.room.message", %{"body" => "pending"})
      |> Map.put("prev_events", ["$missing"])
      |> Event.sign("12", @remote, "ed25519:test", "remote.org")

    assert {:ok, response} = Transactions.receive("remote.org", "missing", transaction([missing]))
    assert response["pdus"][Event.id(missing, "12")]["error"]
    assert Repo.aggregate("matrix_federation_inbox", :count) == 1
  end

  test "an empty successful transaction result does not trap an already-known event in the queue",
       ctx do
    {:ok, first} = Graph.send(ctx.room.id, ctx.user, "m.room.message", %{"body" => "known"})
    {:ok, second} = Graph.send(ctx.room.id, ctx.user, "m.room.message", %{"body" => "new"})

    assert :delivered =
             Outbox.deliver_once(fn :put, "remote.org", _, body ->
               assert Enum.any?(body["pdus"], &(Event.id(&1, "12") == first["event_id"]))
               {:ok, %{"pdus" => %{}}}
             end)

    assert :delivered =
             Outbox.deliver_once(fn :put, "remote.org", _, body ->
               assert Enum.any?(body["pdus"], &(Event.id(&1, "12") == second["event_id"]))
               {:ok, %{"pdus" => %{second["event_id"] => %{}}}}
             end)
  end

  test "a permanent HTTP rejection does not block later transactions to the same server", ctx do
    {:ok, first} = Graph.send(ctx.room.id, ctx.user, "m.room.message", %{"body" => "rejected"})
    {:ok, second} = Graph.send(ctx.room.id, ctx.user, "m.room.message", %{"body" => "later"})

    assert :delivered =
             Outbox.deliver_once(fn :put, "remote.org", _, _ ->
               {:error, {:http, 400, %{"errcode" => "M_BAD_JSON"}}}
             end)

    assert Repo.exists?(
             from o in "matrix_federation_outbox",
               where: o.event_id == ^first["event_id"] and not is_nil(o.failed_at)
           )

    assert :delivered =
             Outbox.deliver_once(fn :put, "remote.org", _, body ->
               assert Enum.any?(body["pdus"], &(Event.id(&1, "12") == second["event_id"]))
               {:ok, %{"pdus" => %{second["event_id"] => %{}}}}
             end)
  end

  test "outbound retries preserve their transaction ID and body and block later deliveries to that destination",
       ctx do
    {:ok, first} = Graph.send(ctx.room.id, ctx.user, "m.room.message", %{"body" => "first"})
    {:ok, _} = Graph.send(ctx.room.id, ctx.user, "m.room.message", %{"body" => "second"})
    parent = self()

    failed = fn :put, "remote.org", path, body ->
      send(parent, {:attempt, path, body})
      {:error, :unavailable}
    end

    assert :delivered = Outbox.deliver_once(failed)
    assert_receive {:attempt, path, body}
    assert :idle = Outbox.deliver_once(failed)

    Repo.update_all(
      from(o in "matrix_federation_outbox", where: o.event_id == ^first["event_id"]),
      set: [available_at: DateTime.add(ClientStore.now(), -1, :second)]
    )

    success = fn :put, "remote.org", next_path, next_body ->
      send(parent, {:retry, next_path, next_body})
      {:ok, %{"pdus" => %{first["event_id"] => %{}}}}
    end

    assert :delivered = Outbox.deliver_once(success)
    assert_receive {:retry, ^path, ^body}

    assert Repo.one(
             from o in "matrix_federation_outbox",
               where: o.event_id == ^first["event_id"],
               select: o.delivered_at
           )
  end

  test "a queued child recovers its missing predecessor using verified state and auth before becoming visible",
       ctx do
    first = remote(ctx.room.id, "m.room.message", %{"body" => "missing parent"})

    second =
      remote(ctx.room.id, "m.room.message", %{"body" => "queued child"})
      |> Map.put("prev_events", [Event.id(first, "12")])
      |> Map.put("depth", first["depth"] + 1)
      |> Event.sign("12", @remote, "ed25519:test", "remote.org")

    assert {:ok, _} = Transactions.receive("remote.org", "gap", transaction([second]))
    refute Graph.event(Event.id(second, "12"))
    graph = Graph.load_graph(ctx.room.id)

    state =
      Enum.map(Graph.decode_state(Graph.room(ctx.room.id).current_state), fn {_, id} ->
        Map.drop(graph[id], ["event_id", :auth_rejected])
      end)

    auth = Enum.map(graph, fn {_, e} -> Map.drop(e, ["event_id", :auth_rejected]) end)

    request = fn :get, "remote.org", path, nil ->
      if String.contains?(path, "/event/"),
        do: {:ok, %{"pdus" => [first]}},
        else: {:ok, %{"pdus" => state, "auth_chain" => auth}}
    end

    assert :recovered = Inbox.recover_once(request)
    assert Repo.aggregate("matrix_federation_inbox", :count) == 0
    assert Graph.event(Event.id(first, "12"))
    assert Graph.event(Event.id(second, "12"))

    assert Repo.exists?(
             from e in LakehouseMatrix.Schema.RoomEvent,
               where: e.event_id == ^Event.id(second, "12") and e.timeline_visible
           )
  end

  test "an untrusted recovery response cannot replace local room state", ctx do
    child =
      remote(ctx.room.id, "m.room.message", %{"body" => "pending"})
      |> Map.put("prev_events", ["$absent"])
      |> Event.sign("12", @remote, "ed25519:test", "remote.org")

    assert {:ok, _} = Transactions.receive("remote.org", "bad-gap", transaction([child]))
    before = Graph.room(ctx.room.id).current_state
    request = fn :get, _, _, nil -> {:ok, %{"pdus" => [child], "auth_chain" => []}} end
    assert :recovered = Inbox.recover_once(request)
    assert Graph.room(ctx.room.id).current_state == before
    refute Graph.event(Event.id(child, "12"))
    assert Repo.aggregate("matrix_federation_inbox", :count) == 1
  end

  test "remote device messages preserve the authenticated sender, expand wildcards and deduplicate retries",
       ctx do
    content = %{
      "sender" => @bob,
      "type" => "m.room.encrypted",
      "message_id" => "one",
      "messages" => %{
        ctx.user => %{
          "*" => %{"algorithm" => "m.olm.v1.curve25519-aes-sha2", "ciphertext" => %{}}
        }
      }
    }

    edu = %{"edu_type" => "m.direct_to_device", "content" => content}
    assert {:ok, _} = Edus.receive("remote.org", edu)
    assert {:ok, _} = Edus.receive("remote.org", edu)

    assert [%{"sender" => @bob, "type" => "m.room.encrypted"}] =
             ClientStore.to_device(ctx.alice.id, "A", 0, ClientStore.position())
             |> Enum.map(&Map.take(&1, ~w(sender type)))

    assert {:error, :invalid_param} = Edus.receive("evil.org", edu)
  end

  test "device-list gaps invalidate cached keys rather than trusting partial updates", ctx do
    update = fn stream, previous ->
      %{
        "edu_type" => "m.device_list_update",
        "content" => %{
          "user_id" => @bob,
          "device_id" => "B",
          "stream_id" => stream,
          "prev_id" => previous,
          "keys" => %{"user_id" => @bob, "device_id" => "B"}
        }
      }
    end

    assert {:ok, _} = Edus.receive("remote.org", update.(1, []))
    refute Repo.one(from u in "matrix_remote_users", where: u.user_id == @bob, select: u.valid)

    Repo.update_all(from(u in "matrix_remote_users", where: u.user_id == @bob),
      set: [valid: true]
    )

    assert {:ok, _} = Edus.receive("remote.org", update.(2, [1]))
    assert Repo.one(from u in "matrix_remote_users", where: u.user_id == @bob, select: u.valid)

    assert Repo.one(
             from d in "matrix_remote_devices", where: d.user_id == @bob, select: d.device_id
           ) == "B"

    assert {:ok, _} = Edus.receive("remote.org", update.(5, [4]))
    refute Repo.one(from u in "matrix_remote_users", where: u.user_id == @bob, select: u.valid)
    assert Repo.exists?(from e in "matrix_device_changes", where: e.user_id == @bob)
    assert ctx.room.id
  end

  test "public receipts federate with full user IDs and private receipts stay local", ctx do
    alias LakehouseMatrix.{ClientRooms, ClientSync}
    {:ok, message} = Graph.send(ctx.room.id, ctx.user, "m.room.message", %{"body" => "read"})
    ref = Identity.room_id(ctx.room.id)
    assert {:ok, %{}} = ClientRooms.receipt(ctx.alice.id, ref, "m.read", message["event_id"], %{})
    count = Repo.aggregate(from(o in "matrix_federation_outbox", where: o.kind == "edu"), :count)
    assert count == 1

    assert {:ok, %{}} =
             ClientRooms.receipt(ctx.alice.id, ref, "m.read.private", message["event_id"], %{})

    assert Repo.aggregate(from(o in "matrix_federation_outbox", where: o.kind == "edu"), :count) ==
             count

    edu = %{
      "edu_type" => "m.receipt",
      "content" => %{
        ref => %{
          "m.read" => %{
            @bob => %{"event_ids" => [message["event_id"]], "data" => %{"ts" => 123}}
          }
        }
      }
    }

    assert {:ok, _} = Edus.receive("remote.org", edu)
    [receipt] = ClientSync.receipts(ctx.alice.id, ctx.room.id, 0, ClientStore.position())
    users = receipt["content"][message["event_id"]]["m.read"]
    assert users[ctx.user]
    assert users[@bob] == %{"ts" => 123}
    refute Map.has_key?(users, Identity.user_id(@bob))
  end
end
