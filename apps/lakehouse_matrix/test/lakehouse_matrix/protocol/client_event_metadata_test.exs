defmodule LakehouseMatrix.Protocol.ClientEventMetadataTest do
  use LakehouseMatrix.DataCase, async: false
  alias LakehouseMatrix.{ClientRooms, ClientSync, Erasure, Fixtures, Identity, Matrix}

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
      for {k, v} <- old do
        if is_nil(v),
          do: Application.delete_env(:lakehouse_matrix, k),
          else: Application.put_env(:lakehouse_matrix, k, v)
      end
    end)

    alice = Fixtures.user_fixture("alice")
    bob = Fixtures.user_fixture("bob")
    {:ok, %{"room_id" => ref}} = ClientRooms.create(alice.id, %{"preset" => "public_chat"})
    {:ok, local} = Identity.parse_room_id(ref)
    %{alice: alice, bob: bob, ref: ref, local: local}
  end

  test "state replacement IDs remain visible while prior content follows history visibility", c do
    {:ok, _} =
      ClientRooms.put_state(c.alice.id, c.ref, "m.room.history_visibility", "", %{
        "history_visibility" => "joined"
      })

    {:ok, old} =
      ClientRooms.put_state(c.alice.id, c.ref, "m.room.topic", "", %{
        "topic" => "Before Bob joined"
      })

    {:ok, _} = Matrix.join_room(c.bob.id, c.ref)

    {:ok, latest} =
      ClientRooms.put_state(c.alice.id, c.ref, "m.room.topic", "", %{
        "topic" => "After Bob joined"
      })

    assert {:ok, alice} = ClientRooms.event(c.alice.id, c.ref, latest["event_id"])
    assert alice["unsigned"]["replaces_state"] == old["event_id"]
    assert alice["unsigned"]["prev_content"] == %{"topic" => "Before Bob joined"}
    assert {:ok, bob} = ClientRooms.event(c.bob.id, c.ref, latest["event_id"])
    assert bob["unsigned"]["replaces_state"] == old["event_id"]
    refute Map.has_key?(bob["unsigned"], "prev_content")
    assert {:ok, sync} = ClientSync.sync(c.bob.id, "B", %{})

    [topic] =
      Enum.filter(
        sync["rooms"]["join"][c.ref]["timeline"]["events"],
        &(&1["type"] == "m.room.topic")
      )

    assert topic["unsigned"]["replaces_state"] == old["event_id"]
    refute Map.has_key?(topic["unsigned"], "prev_content")
  end

  test "read markers update account data and receipts atomically through the dedicated API", c do
    {:ok, _} = Matrix.join_room(c.bob.id, c.ref)

    {:ok, first} =
      ClientRooms.send(c.alice.id, "A", c.ref, "m.room.message", "first", %{"body" => "First"})

    {:ok, second} =
      ClientRooms.send(c.alice.id, "A", c.ref, "m.room.message", "second", %{"body" => "Second"})

    assert {:ok, %{}} =
             ClientRooms.read_markers(c.bob.id, c.ref, %{
               "m.fully_read" => first["event_id"],
               "m.read" => first["event_id"],
               "m.read.private" => first["event_id"]
             })

    assert LakehouseMatrix.ClientStore.get_data(c.bob.id, c.ref, "m.fully_read") == %{
             "event_id" => first["event_id"]
           }

    assert {:ok, sync} = ClientSync.sync(c.bob.id, "B", %{})

    assert %{"type" => "m.fully_read", "content" => %{"event_id" => first["event_id"]}} in sync[
             "rooms"
           ]["join"][c.ref]["account_data"]["events"]

    assert {:error, :forbidden} =
             ClientRooms.read_markers(c.bob.id, c.ref, %{
               "m.fully_read" => second["event_id"],
               "m.read" => second["event_id"],
               "m.read.private" => "$unknown"
             })

    assert LakehouseMatrix.ClientStore.get_data(c.bob.id, c.ref, "m.fully_read") == %{
             "event_id" => first["event_id"]
           }

    assert Repo.one(
             from r in "matrix_receipts",
               where: r.principal_id == type(^c.bob.id, :binary_id) and r.type == "m.read",
               select: r.event_id
           ) == first["event_id"]

    assert {:error, :invalid_param} =
             ClientRooms.read_markers(c.bob.id, c.ref, %{"m.fully_read" => false})
  end

  test "erasure and real redaction apply to prior content as well as the current event", c do
    {:ok, _} = Matrix.join_room(c.bob.id, c.ref)

    {:ok, old} =
      ClientRooms.put_state(c.alice.id, c.ref, "m.room.topic", "", %{"topic" => "Erased topic"})

    assert {:ok, :ok} = Repo.transaction(fn -> Erasure.erase!(c.alice.id) end)
    later = Fixtures.user_fixture("later")
    {:ok, _} = Matrix.join_room(later.id, c.ref)

    {:ok, latest} =
      ClientRooms.put_state(c.alice.id, c.ref, "m.room.topic", "", %{"topic" => "New topic"})

    assert {:ok, event} = ClientRooms.event(c.bob.id, c.ref, latest["event_id"])
    assert event["unsigned"]["prev_content"] == %{"topic" => "Erased topic"}
    assert {:ok, pruned} = ClientRooms.event(later.id, c.ref, latest["event_id"])
    assert pruned["unsigned"]["replaces_state"] == old["event_id"]
    assert pruned["unsigned"]["prev_content"] == %{}

    assert {:ok, _} =
             ClientRooms.redact(c.alice.id, "A", c.ref, old["event_id"], "redact-prior", %{})

    assert {:ok, event} = ClientRooms.event(c.bob.id, c.ref, latest["event_id"])
    assert event["unsigned"]["prev_content"] == %{}
  end
end
