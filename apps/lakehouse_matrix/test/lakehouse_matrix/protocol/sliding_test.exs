defmodule LakehouseMatrix.Protocol.SlidingTest do
  use LakehouseMatrix.DataCase, async: false

  alias LakehouseMatrix.{
    ClientHistory,
    ClientRooms,
    ClientStore,
    ClientSync,
    Fixtures,
    Identity,
    Matrix,
    SlidingSync
  }

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

    %{alice: Fixtures.user_fixture("alice"), bob: Fixtures.user_fixture("bob")}
  end

  defp list,
    do: %{
      "lists" => %{
        "all" => %{
          "range" => [0, 20],
          "timeline_limit" => 10,
          "required_state" => %{"include" => [%{}], "lazy_members" => true}
        }
      }
    }

  defp room(ctx, params), do: ClientRooms.create(ctx.alice.id, params)

  test "current proposal on the unstable endpoint includes knocks and does not stick request parameters",
       ctx do
    {:ok, %{"room_id" => ref}} =
      room(ctx, %{
        "initial_state" => [
          %{
            "type" => "m.room.join_rules",
            "state_key" => "",
            "content" => %{"join_rule" => "knock"}
          }
        ]
      })

    {:ok, _} = ClientRooms.knock(ctx.bob.id, ref, [], %{})
    assert {:ok, first} = SlidingSync.sync(ctx.bob.id, "B", list())
    assert first["rooms"][ref]["membership"] == "knock"

    assert Enum.any?(
             first["rooms"][ref]["stripped_state"],
             &(&1["type"] == "m.room.member" and &1["content"]["membership"] == "knock")
           )

    refute Map.has_key?(first["rooms"][ref], "timeline")
    assert {:ok, next} = SlidingSync.sync(ctx.bob.id, "B", %{"pos" => first["pos"]})
    assert next["lists"] == %{}
    assert next["rooms"] == %{}
    {:ok, local} = Identity.parse_room_id(ref)
    {:ok, _} = LakehouseMatrix.Protocol.Rooms.invite(ctx.alice.id, local, Identity.user_id("bob"))
    {:ok, _} = Matrix.join_room(ctx.bob.id, ref)

    assert {:ok, accepted} =
             SlidingSync.sync(ctx.bob.id, "B", Map.put(list(), "pos", next["pos"]))

    assert accepted["rooms"][ref]["initial"]
    assert accepted["rooms"][ref]["membership"] == "join"
    assert is_list(accepted["rooms"][ref]["timeline"])
  end

  test "sliding positions paginate history and remain private to their user and device", ctx do
    {:ok, %{"room_id" => ref}} = room(ctx, %{"preset" => "public_chat"})
    {:ok, local} = Identity.parse_room_id(ref)
    {:ok, _} = Matrix.join_room(ctx.bob.id, ref)

    {:ok, before} =
      ClientRooms.send(ctx.alice.id, "A", ref, "m.room.message", "before", %{"body" => "before"})

    {:ok, first} = SlidingSync.sync(ctx.alice.id, "A", list())

    {:ok, after_event} =
      ClientRooms.send(ctx.alice.id, "A", ref, "m.room.message", "after", %{"body" => "after"})

    assert {:ok, history} =
             ClientHistory.page(ctx.alice.id, "A", local, %{
               "from" => first["pos"],
               "dir" => "b",
               "limit" => 100
             })

    assert Enum.any?(history["chunk"], &(&1["event_id"] == before["event_id"]))
    refute Enum.any?(history["chunk"], &(&1["event_id"] == after_event["event_id"]))

    assert {:error, :invalid_cursor} =
             ClientHistory.page(ctx.alice.id, "other", local, %{"from" => first["pos"]})

    assert {:error, :invalid_cursor} =
             ClientHistory.page(ctx.bob.id, "A", local, %{"from" => first["pos"]})
  end

  test "kicks are listed after a new connection and subscription history stops at departure",
       ctx do
    {:ok, %{"room_id" => ref}} = room(ctx, %{"preset" => "public_chat"})
    {:ok, _} = Matrix.join_room(ctx.bob.id, ref)
    {:ok, _} = ClientRooms.moderate(ctx.alice.id, ref, "kick", Identity.user_id("bob"), "depart")

    {:ok, _} =
      ClientRooms.put_state(ctx.alice.id, ref, "m.room.topic", "", %{
        "topic" => "private later topic"
      })

    {:ok, later} =
      ClientRooms.send(ctx.alice.id, "A", ref, "m.room.message", "later", %{
        "body" => "private later message"
      })

    assert {:ok, first} = SlidingSync.sync(ctx.bob.id, "B", list())
    payload = first["rooms"][ref]
    assert payload["membership"] == "leave"
    refute Enum.any?(payload["timeline"], &(&1["event_id"] == later["event_id"]))

    refute Enum.any?(
             payload["required_state"],
             &(&1["content"]["topic"] == "private later topic")
           )

    assert {:ok, %{}} = ClientRooms.forget(ctx.bob.id, ref)

    assert {:ok, forgotten} =
             SlidingSync.sync(ctx.bob.id, "B", Map.put(list(), "pos", first["pos"]))

    refute Map.has_key?(forgotten["rooms"], ref)
    assert forgotten["lists"]["all"]["count"] == 0
  end

  test "incremental lazy membership includes resolved changes and deleted-state stubs", ctx do
    {:ok, %{"room_id" => ref}} = room(ctx, %{"preset" => "public_chat"})
    {:ok, local} = Identity.parse_room_id(ref)
    {:ok, _} = ClientRooms.put_state(ctx.alice.id, ref, "m.custom", "", %{"value" => "old"})
    {:ok, first} = SlidingSync.sync(ctx.alice.id, "A", list())
    # A resolved-state delta can be absent from a filtered/non-visible timeline.
    {:ok, joined} = Matrix.join_room(ctx.bob.id, ref)

    member_id =
      Graph.decode_state(Graph.room(local).current_state)[
        {"m.room.member", Identity.user_id("bob")}
      ]

    Repo.get_by!(LakehouseMatrix.Schema.RoomEvent, event_id: member_id)
    |> Ecto.Changeset.change(timeline_visible: false)
    |> Repo.update!()

    assert is_map(joined)

    {:ok, _} =
      Repo.transaction(fn ->
        ClientStore.lock!()

        Repo.insert_all("matrix_state_changes", [
          %{
            local_room_id: ClientStore.dump_id(local),
            type: "m.custom",
            state_key: "",
            event_id: nil
          }
        ])
      end)

    assert {:ok, delta} =
             SlidingSync.sync(ctx.alice.id, "A", Map.put(list(), "pos", first["pos"]))

    required = delta["rooms"][ref]["required_state"]

    assert Enum.any?(
             required,
             &(&1["type"] == "m.room.member" and &1["state_key"] == Identity.user_id("bob"))
           )

    assert %{"type" => "m.custom", "state_key" => ""} in required
    assert {:ok, next} = ClientSync.history_cursor(delta["pos"], ctx.alice.id, "A", local)
    assert next <= ClientStore.position()
  end
end
