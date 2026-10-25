defmodule LakehouseMatrix.Protocol.RelationsTest do
  use LakehouseMatrix.DataCase, async: false

  alias LakehouseMatrix.{
    ClientHistory,
    ClientRelations,
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

    alice = Fixtures.user_fixture("alice")
    bob = Fixtures.user_fixture("bob")
    {:ok, %{"room_id" => ref}} = ClientRooms.create(alice.id, %{"preset" => "public_chat"})
    {:ok, local} = Identity.parse_room_id(ref)
    {:ok, _} = Matrix.join_room(bob.id, ref)
    %{alice: alice, bob: bob, ref: ref, local: local}
  end

  defp send(ctx, user, label, relation \\ nil, extra \\ %{}) do
    body = Map.merge(%{"body" => label, "msgtype" => "m.text"}, extra)
    body = if relation, do: Map.put(body, "m.relates_to", relation), else: body
    {:ok, event} = ClientRooms.send(user.id, "A", ctx.ref, "m.room.message", label, body)
    event
  end

  defp rel(type, parent), do: %{"rel_type" => type, "event_id" => parent["event_id"]}
  defp ids(page), do: Enum.map(page["chunk"], & &1["event_id"])

  test "relations filter before the limit, recurse three levels and accept sync/history positions",
       ctx do
    root = send(ctx, ctx.alice, "root")
    first = send(ctx, ctx.bob, "direct", rel("m.reference", root))
    second = send(ctx, ctx.bob, "second", rel("m.reference", first))
    third = send(ctx, ctx.bob, "third", rel("m.reference", second))
    _fourth = send(ctx, ctx.bob, "fourth", rel("m.reference", third))
    {:ok, sync} = ClientSync.sync(ctx.alice.id, "A", %{})
    last = send(ctx, ctx.bob, "last direct", rel("m.reference", root))

    assert {:ok, page} =
             ClientRelations.page(ctx.alice.id, "A", ctx.ref, root["event_id"], %{
               "limit" => 1,
               "relType" => "m.reference",
               "eventType" => "m.room.message"
             })

    assert ids(page) == [last["event_id"]]

    assert {:ok, next} =
             ClientRelations.page(ctx.alice.id, "A", ctx.ref, root["event_id"], %{
               "from" => page["next_batch"],
               "limit" => 1
             })

    assert ids(next) == [first["event_id"]]
    refute Map.has_key?(next, "next_batch")

    assert {:ok, recursive} =
             ClientRelations.page(ctx.alice.id, "A", ctx.ref, root["event_id"], %{
               "recurse" => "true"
             })

    assert ids(recursive) == Enum.map([last, third, second, first], & &1["event_id"])
    assert recursive["recursion_depth"] == 3

    assert {:ok, past} =
             ClientRelations.page(ctx.alice.id, "A", ctx.ref, root["event_id"], %{
               "from" => sync["next_batch"]
             })

    assert ids(past) == [first["event_id"]]

    assert {:error, :invalid_cursor} =
             ClientRelations.page(ctx.bob.id, "A", ctx.ref, root["event_id"], %{
               "from" => page["next_batch"]
             })

    assert {:ok, empty} =
             ClientRelations.page(ctx.alice.id, "A", ctx.ref, root["event_id"], %{
               "eventType" => "m.reaction"
             })

    assert empty["chunk"] == []
  end

  test "bundles validate edits, aggregate threads and references, and remove redacted children",
       ctx do
    root = send(ctx, ctx.alice, "original")

    valid =
      send(ctx, ctx.alice, "edit", rel("m.replace", root), %{
        "m.new_content" => %{"body" => "updated"}
      })

    _wrong_user =
      send(ctx, ctx.bob, "forged edit", rel("m.replace", root), %{
        "m.new_content" => %{"body" => "forged"}
      })

    _missing_content = send(ctx, ctx.alice, "invalid edit", rel("m.replace", root))
    reply = send(ctx, ctx.bob, "reply", rel("m.thread", root))
    reference = send(ctx, ctx.bob, "reference", rel("m.reference", root))
    assert {:ok, event} = ClientRooms.event(ctx.alice.id, ctx.ref, root["event_id"])
    aggregate = event["unsigned"]["m.relations"]
    assert aggregate["m.replace"]["event_id"] == valid["event_id"]
    assert aggregate["m.thread"]["latest_event"]["event_id"] == reply["event_id"]
    assert aggregate["m.thread"]["count"] == 1
    assert aggregate["m.thread"]["current_user_participated"]
    assert aggregate["m.reference"]["chunk"] == [%{"event_id" => reference["event_id"]}]
    refute Map.has_key?(aggregate, "m.annotation")

    assert {:ok, _} =
             ClientRooms.redact(
               ctx.bob.id,
               "A",
               ctx.ref,
               reference["event_id"],
               "remove reference",
               %{}
             )

    assert {:ok, redacted} = ClientRooms.event(ctx.alice.id, ctx.ref, root["event_id"])
    refute Map.has_key?(redacted["unsigned"]["m.relations"], "m.reference")

    assert {:ok, _} =
             ClientRooms.redact(
               ctx.alice.id,
               "A",
               ctx.ref,
               root["event_id"],
               "remove parent",
               %{}
             )

    assert {:ok, redacted_root} = ClientRooms.event(ctx.alice.id, ctx.ref, root["event_id"])
    refute Map.has_key?(redacted_root["unsigned"]["m.relations"], "m.replace")
    assert redacted_root["unsigned"]["m.relations"]["m.thread"]["count"] == 1
  end

  test "aggregation honors departure boundaries, ignored senders and a sync high watermark",
       ctx do
    root = send(ctx, ctx.alice, "root")
    reply = send(ctx, ctx.alice, "first reply", rel("m.thread", root))
    high = ClientStore.position()
    {:ok, _} = Matrix.leave_room(ctx.bob.id, ctx.ref)
    later = send(ctx, ctx.alice, "later reply", rel("m.thread", root))
    assert {:ok, event} = ClientRooms.event(ctx.bob.id, ctx.ref, root["event_id"])
    assert event["unsigned"]["m.relations"]["m.thread"]["count"] == 1

    assert event["unsigned"]["m.relations"]["m.thread"]["latest_event"]["event_id"] ==
             reply["event_id"]

    {:ok, raw_root} = ClientHistory.event(ctx.alice.id, ctx.local, root["event_id"])
    [as_of] = ClientRelations.bundle(ctx.alice.id, ctx.local, [raw_root], high)
    assert as_of["unsigned"]["m.relations"]["m.thread"]["count"] == 1

    {:ok, _} =
      ClientStore.put_data(ctx.bob.id, "", "m.ignored_user_list", %{
        "ignored_users" => %{Identity.user_id("alice") => %{}}
      })

    assert {:ok, ignored} = ClientRooms.event(ctx.bob.id, ctx.ref, root["event_id"])
    refute get_in(ignored, ["unsigned", "m.relations"])

    assert {:error, :not_found} =
             ClientRelations.page(ctx.bob.id, "B", ctx.ref, later["event_id"], %{})
  end

  test "duplicate annotations are atomic, retries are idempotent and redaction permits a replacement",
       ctx do
    root = send(ctx, ctx.alice, "root")
    reaction = %{"m.relates_to" => Map.put(rel("m.annotation", root), "key", "👍")}

    assert {:ok, first} =
             ClientRooms.send(ctx.bob.id, "B", ctx.ref, "m.reaction", "one", reaction)

    assert {:ok, ^first} =
             ClientRooms.send(ctx.bob.id, "B", ctx.ref, "m.reaction", "one", reaction)

    assert {:error, :duplicate_annotation} =
             ClientRooms.send(ctx.bob.id, "B", ctx.ref, "m.reaction", "two", reaction)

    assert {:error, :invalid_param} =
             ClientRooms.send(ctx.alice.id, "A", ctx.ref, "m.room.message", "nested", %{
               "m.relates_to" => rel("m.thread", first)
             })

    assert {:ok, _} =
             ClientRooms.redact(ctx.bob.id, "B", ctx.ref, first["event_id"], "redact", %{})

    assert {:ok, _} = ClientRooms.send(ctx.bob.id, "B", ctx.ref, "m.reaction", "two", reaction)
  end

  test "thread roots paginate by latest reply, participation and device, with edits on the latest reply",
       ctx do
    root_a = send(ctx, ctx.alice, "a")
    root_b = send(ctx, ctx.alice, "b")
    root_c = send(ctx, ctx.alice, "c")
    _reply_a = send(ctx, ctx.alice, "reply a", rel("m.thread", root_a))
    _reply_c = send(ctx, ctx.alice, "reply c", rel("m.thread", root_c))
    reply_b = send(ctx, ctx.bob, "reply b", rel("m.thread", root_b))

    edit =
      send(ctx, ctx.bob, "edited b", rel("m.replace", reply_b), %{
        "m.new_content" => %{"body" => "edited"}
      })

    assert {:ok, page} = ClientRelations.threads(ctx.alice.id, "A", ctx.ref, %{"limit" => 1})
    assert ids(page) == [root_b["event_id"]]

    assert get_in(hd(page["chunk"]), [
             "unsigned",
             "m.relations",
             "m.thread",
             "latest_event",
             "unsigned",
             "m.relations",
             "m.replace",
             "event_id"
           ]) == edit["event_id"]

    assert {:ok, next} =
             ClientRelations.threads(ctx.alice.id, "A", ctx.ref, %{
               "from" => page["next_batch"],
               "limit" => 1
             })

    assert ids(next) == [root_c["event_id"]]

    assert {:ok, last} =
             ClientRelations.threads(ctx.alice.id, "A", ctx.ref, %{
               "from" => next["next_batch"],
               "limit" => 1
             })

    assert ids(last) == [root_a["event_id"]]
    refute last["next_batch"]

    assert {:error, :invalid_cursor} =
             ClientRelations.threads(ctx.alice.id, "other", ctx.ref, %{
               "from" => page["next_batch"]
             })

    assert {:error, :invalid_cursor} =
             ClientRelations.threads(ctx.alice.id, "A", ctx.ref, %{
               "from" => page["next_batch"],
               "include" => "participated"
             })

    assert {:ok, participated} =
             ClientRelations.threads(ctx.bob.id, "B", ctx.ref, %{"include" => "participated"})

    assert ids(participated) == [root_b["event_id"]]
    assert {:ok, history} = ClientHistory.page(ctx.alice.id, "A", ctx.local, %{"limit" => 100})

    assert Enum.find(history["chunk"], &(&1["event_id"] == root_b["event_id"]))["unsigned"][
             "m.relations"
           ]["m.thread"]
  end
end
