defmodule LakehouseMatrix.ClientRoomDataTest do
  use LakehouseMatrix.DataCase, async: false

  alias LakehouseMatrix.{
    ClientRoomData,
    ClientRooms,
    ClientStore,
    ClientSync,
    Fixtures,
    Identity,
    Matrix
  }

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

    %{
      alice: Fixtures.user_fixture("alice"),
      bob: Fixtures.user_fixture("bob"),
      outsider: Fixtures.user_fixture("outsider")
    }
  end

  defp shared(ctx) do
    {:ok, %{"room_id" => ref}} = ClientRooms.create(ctx.alice.id, %{"preset" => "public_chat"})
    {:ok, _} = Matrix.join_room(ctx.bob.id, ref)
    ref
  end

  test "mutual-room pages bind user/device, exclude new joins and recheck current membership",
       ctx do
    first = shared(ctx)
    second = shared(ctx)
    {:ok, _} = ClientRooms.create(ctx.bob.id, %{})
    {:ok, _} = ClientRooms.create(ctx.alice.id, %{})
    params = %{"user_id" => Identity.user_id("bob")}
    {:ok, all} = ClientRoomData.mutual(ctx.alice.id, "A", params)
    assert all == %{"joined" => Enum.sort([first, second]), "count" => 2}

    assert {:ok, %{"joined" => [], "count" => 0}} =
             ClientRoomData.mutual(ctx.alice.id, "A", %{"user_id" => "@unknown:remote.example"})

    assert {:error, :invalid_param} =
             ClientRoomData.mutual(ctx.alice.id, "A", %{"user_id" => Identity.user_id("alice")})

    {:ok, page} = ClientRoomData.mutual(ctx.alice.id, "A", params, 1)
    cursor = Map.put(params, "from", page["next_batch"])
    assert {:error, :invalid_cursor} = ClientRoomData.mutual(ctx.alice.id, "OTHER", cursor)

    assert {:error, :invalid_cursor} =
             ClientRoomData.mutual(
               ctx.alice.id,
               "A",
               Map.put(cursor, "user_id", Identity.user_id("outsider"))
             )

    _ = shared(ctx)
    {:ok, next} = ClientRoomData.mutual(ctx.alice.id, "A", cursor)
    assert next["count"] == 2
    assert page["joined"] ++ next["joined"] == Enum.sort([first, second])
    remaining = hd(next["joined"])
    {:ok, _} = Matrix.leave_room(ctx.bob.id, remaining)

    assert {:ok, %{"joined" => [], "count" => 1}} =
             ClientRoomData.mutual(ctx.alice.id, "A", cursor)
  end

  test "tags preserve floating order, stay private, sync as account data and can be prepared before joining",
       ctx do
    ref = shared(ctx)

    assert {:ok, %{}} =
             ClientRoomData.tag(ctx.alice.id, ref, "m.favourite", "PUT", %{"order" => 0.25})

    assert {:ok, %{"tags" => %{"m.favourite" => %{"order" => 0.25}}}} =
             ClientRoomData.tags(ctx.alice.id, ref)

    assert {:ok, %{"tags" => %{}}} = ClientRoomData.tags(ctx.bob.id, ref)
    {:ok, sync} = ClientSync.sync(ctx.alice.id, "A", %{})

    assert Enum.any?(
             get_in(sync, ["rooms", "join", ref, "account_data", "events"]),
             &(&1 == %{
                 "type" => "m.tag",
                 "content" => %{"tags" => %{"m.favourite" => %{"order" => 0.25}}}
               })
           )

    assert {:error, :invalid_param} =
             ClientRoomData.tag(ctx.alice.id, ref, "u.work", "PUT", %{"order" => 1.1})

    assert {:error, :invalid_param} = ClientRoomData.tags(ctx.alice.id, "not a room")
    assert {:ok, %{}} = ClientRoomData.tag(ctx.alice.id, ref, "m.favourite", "DELETE", %{})
    assert ClientStore.get_data(ctx.alice.id, ref, "m.tag") == %{"tags" => %{}}
    unknown = "!" <> String.duplicate("a", 43)
    assert {:ok, %{}} = ClientRoomData.tag(ctx.alice.id, unknown, "u.work", "PUT", %{})
    assert {:ok, %{"tags" => %{"u.work" => %{}}}} = ClientRoomData.tags(ctx.alice.id, unknown)
  end
end
