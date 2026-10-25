defmodule LakehouseMatrix.NotificationsTest do
  use LakehouseMatrix.DataCase, async: false
  alias LakehouseIam.Repo

  alias LakehouseMatrix.{
    ClientRooms,
    ClientStore,
    ClientSync,
    Fixtures,
    Identity,
    Matrix,
    Notifications,
    Pushers,
    PushRules,
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

    alice = Fixtures.user_fixture("alice")
    bob = Fixtures.user_fixture("bob")
    {:ok, %{"room_id" => ref}} = ClientRooms.create(alice.id, %{"preset" => "public_chat"})
    {:ok, _} = Matrix.join_room(bob.id, ref)
    {:ok, local} = Identity.parse_room_id(ref)
    %{alice: alice, bob: bob, ref: ref, local: local}
  end

  defp message(ctx, txn, content \\ %{}) do
    {:ok, %{"event_id" => id}} =
      ClientRooms.send(
        ctx.alice.id,
        "A",
        ctx.ref,
        "m.room.message",
        txn,
        Map.merge(%{"msgtype" => "m.text", "body" => txn}, content)
      )

    id
  end

  test "default rules use typed properties, escaped paths, bounded globs and v12 creator power",
       ctx do
    event = %{
      "type" => "m.room.message",
      "sender" => Identity.user_id("alice"),
      "content" => %{
        "m.mentions" => %{"user_ids" => [Identity.user_id("bob")], "room" => true},
        "nullable" => nil,
        "boolean" => true
      }
    }

    rules = PushRules.get(ctx.bob.id)
    assert Notifications.highlight?(PushRules.evaluate(rules, event, %{members: 2}))

    assert PushRules.condition?(
             %{"kind" => "event_property_is", "key" => "content.nullable", "value" => nil},
             event,
             %{}
           )

    refute PushRules.condition?(
             %{"kind" => "event_property_is", "key" => "missing", "value" => nil},
             event,
             %{}
           )

    refute PushRules.condition?(
             %{"kind" => "event_property_is", "key" => "content.boolean", "value" => 1},
             event,
             %{}
           )

    refute PushRules.condition?(%{"kind" => "future_condition"}, event, %{})
    assert PushRules.glob?("An exciting triple-whammy", "ex*ple", true)
    refute PushRules.glob?("notexample", "example", true)
    assert PushRules.glob?("Literal *?", "literal \\*\\?")
    refute PushRules.glob?(true, "*")
    state = LakehouseMatrix.Federation.RoomAccess.state(Graph.room(ctx.local))

    assert PushRules.condition?(
             %{"kind" => "sender_notification_permission", "key" => "room"},
             event,
             %{state: state, version: "12"}
           )

    refute PushRules.condition?(
             %{"kind" => "sender_notification_permission", "key" => "room"},
             Map.put(event, "sender", Identity.user_id("bob")),
             %{state: state, version: "12"}
           )
  end

  test "rule mutations preserve priority, user enablement, master override and editable default actions",
       ctx do
    owner = ctx.bob.id

    for id <- ~w(first second third),
        do:
          assert(
            {:ok, %{}} =
              PushRules.mutate(owner, "override", id, "PUT", %{
                "actions" => ["notify"],
                "conditions" => []
              })
          )

    {:ok, _} =
      PushRules.mutate(owner, "override", "middle", "PUT", %{
        "actions" => ["dont_notify"],
        "before" => "second",
        "after" => "third"
      })

    assert Enum.map(PushRules.get(owner)["global"]["override"] |> Enum.take(5), & &1["rule_id"]) ==
             [".m.rule.master", "third", "middle", "second", "first"]

    {:ok, _} =
      PushRules.mutate(owner, "override", "middle", "PUT", %{"enabled" => false}, "enabled")

    {:ok, _} = PushRules.mutate(owner, "override", "middle", "PUT", %{"actions" => []})
    assert {:ok, %{"enabled" => false}} = PushRules.fetch(owner, "override", "middle", "enabled")

    assert {:error, :invalid_param} =
             PushRules.mutate(owner, "override", "bad", "PUT", %{
               "actions" => [],
               "before" => ".m.rule.master"
             })

    assert {:error, :invalid_param} =
             PushRules.mutate(owner, "override", ".m.rule.master", "DELETE", %{})

    {:ok, _} =
      PushRules.mutate(
        owner,
        "override",
        ".m.rule.master",
        "PUT",
        %{"enabled" => true},
        "enabled"
      )

    assert [] ==
             PushRules.evaluate(PushRules.get(owner), %{"type" => "m.room.message"}, %{members: 2})

    assert Enum.any?(ClientStore.account_data(owner), &(&1["type"] == "m.push_rules"))
  end

  test "notifications and both sync counts honor mentions, suppression, receipts and historical delivery boundaries",
       ctx do
    {:ok, initial} = ClientSync.sync(ctx.bob.id, "B", %{})
    assert Enum.any?(initial["account_data"]["events"], &(&1["type"] == "m.push_rules"))
    first = message(ctx, "ordinary")

    mention =
      message(ctx, "mention", %{"m.mentions" => %{"user_ids" => [Identity.user_id("bob")]}})

    _ = message(ctx, "notice", %{"msgtype" => "m.notice"})

    _ =
      message(ctx, "edit", %{
        "m.relates_to" => %{"rel_type" => "m.replace", "event_id" => first},
        "m.new_content" => %{"body" => "edited", "msgtype" => "m.text"}
      })

    high = ClientStore.position()

    assert Notifications.counts(ctx.bob.id, ctx.local) == %{
             "notification_count" => 2,
             "highlight_count" => 1
           }

    assert Notifications.counts(ctx.alice.id, ctx.local)["notification_count"] == 0
    {:ok, ordinary} = ClientSync.sync(ctx.bob.id, "B", %{"since" => initial["next_batch"]})

    assert get_in(ordinary, [
             "rooms",
             "join",
             ctx.ref,
             "unread_notifications",
             "notification_count"
           ]) == 2

    {:ok, sliding} =
      SlidingSync.sync(ctx.bob.id, "S", %{
        "room_subscriptions" => %{ctx.ref => %{"timeline_limit" => 0}}
      })

    assert get_in(sliding, ["rooms", ctx.ref, "highlight_count"]) == 1
    {:ok, page} = Notifications.page(ctx.bob.id, "B", %{"only" => "highlight"})
    assert [%{"event" => %{"event_id" => ^mention}, "read" => false}] = page["notifications"]
    assert {:ok, _} = ClientRooms.receipt(ctx.bob.id, ctx.ref, "m.read.private", mention, %{})
    assert Notifications.counts(ctx.bob.id, ctx.local)["notification_count"] == 0

    assert Notifications.counts(ctx.bob.id, ctx.local, high)["notification_count"] == 2
    assert {:ok, _} = ClientRooms.receipt(ctx.bob.id, ctx.ref, "m.read.private", first, %{})
    assert Notifications.counts(ctx.bob.id, ctx.local)["notification_count"] == 0
    {:ok, read} = ClientSync.sync(ctx.bob.id, "B", %{"since" => ordinary["next_batch"]})

    assert get_in(read, ["rooms", "join", ctx.ref, "unread_notifications", "notification_count"]) ==
             0
  end

  test "pagination binds device and filter, freezes its high watermark and hides ignored or forgotten rooms",
       ctx do
    first = message(ctx, "first")
    second = message(ctx, "second")
    {:ok, page} = Notifications.page(ctx.bob.id, "B", %{"limit" => 1})
    assert [%{"event" => %{"event_id" => ^second}}] = page["notifications"]
    _ = message(ctx, "later")
    token = page["next_token"]
    assert {:error, :invalid_cursor} = Notifications.page(ctx.bob.id, "OTHER", %{"from" => token})

    assert {:error, :invalid_cursor} =
             Notifications.page(ctx.bob.id, "B", %{"from" => token, "only" => "highlight"})

    {:ok, next} = Notifications.page(ctx.bob.id, "B", %{"from" => token})
    assert [%{"event" => %{"event_id" => ^first}}] = next["notifications"]

    {:ok, _} =
      ClientStore.put_data(ctx.bob.id, "", "m.ignored_user_list", %{
        "ignored_users" => %{Identity.user_id("alice") => %{}}
      })

    assert {:ok, %{"notifications" => []}} = Notifications.page(ctx.bob.id, "B", %{})
    assert Notifications.counts(ctx.bob.id, ctx.local)["notification_count"] == 0

    {:ok, tombstone} =
      ClientRooms.put_state(ctx.alice.id, ctx.ref, "m.room.tombstone", "", %{
        "replacement_room" => "!replacement:example.org",
        "body" => "Upgraded"
      })

    {:ok, state_notices} = Notifications.page(ctx.bob.id, "B", %{})

    assert [%{"event" => %{"type" => "m.room.tombstone", "event_id" => tombstone_id}}] =
             state_notices["notifications"]

    assert tombstone_id == tombstone["event_id"]
    {:ok, _} = ClientStore.put_data(ctx.bob.id, "", "m.ignored_user_list", %{})
    {:ok, _} = Matrix.leave_room(ctx.bob.id, ctx.ref)
    {:ok, _} = ClientRooms.forget(ctx.bob.id, ctx.ref)
    assert {:ok, %{"notifications" => []}} = Notifications.page(ctx.bob.id, "B", %{})
  end

  test "thread receipts clear only their own stream and reject unrelated target/thread combinations",
       ctx do
    root = message(ctx, "thread root")

    reply =
      message(ctx, "thread reply", %{
        "m.relates_to" => %{"rel_type" => "m.thread", "event_id" => root}
      })

    main = message(ctx, "main timeline")
    assert Notifications.counts(ctx.bob.id, ctx.local)["notification_count"] == 3

    assert {:error, :forbidden} =
             ClientRooms.receipt(ctx.bob.id, ctx.ref, "m.read.private", main, %{
               "thread_id" => root
             })

    assert {:error, :forbidden} =
             ClientRooms.receipt(ctx.bob.id, ctx.ref, "m.read.private", reply, %{
               "thread_id" => "main"
             })

    assert {:ok, _} =
             ClientRooms.receipt(ctx.bob.id, ctx.ref, "m.read.private", reply, %{
               "thread_id" => root
             })

    assert Notifications.counts(ctx.bob.id, ctx.local)["notification_count"] == 2

    assert {:ok, _} =
             ClientRooms.receipt(ctx.bob.id, ctx.ref, "m.read", main, %{"thread_id" => "main"})

    assert Notifications.counts(ctx.bob.id, ctx.local)["notification_count"] == 0
  end

  defp pusher(key \\ "key"),
    do: %{
      "app_id" => "cool.gravitas.matrix",
      "pushkey" => key,
      "kind" => "http",
      "app_display_name" => "Matrix",
      "device_display_name" => "Phone",
      "lang" => "en",
      "data" => %{
        "url" => "https://push.example/_matrix/push/v1/notify",
        "format" => "event_id_only"
      }
    }

  test "leased pushes run outside transactions, use event-ID-only payloads, retry and honor read/device revocation",
       ctx do
    {:ok, _} = Pushers.set(ctx.bob.id, "B", pusher())
    id = message(ctx, "push")

    assert :delivered ==
             Pushers.deliver_once(fn _, _ ->
               refute Repo.in_transaction?()
               {:error, :unavailable}
             end)

    Repo.update_all("matrix_push_outbox", set: [available_at: ClientStore.now()])

    assert :delivered ==
             Pushers.deliver_once(fn url, %{"notification" => body} ->
               refute Repo.in_transaction?()
               assert url == "https://push.example/_matrix/push/v1/notify"
               assert body["event_id"] == id and body["counts"]["unread"] == 1
               refute Map.has_key?(body, "content")
               refute Map.has_key?(body, "sender")

               assert [%{"pushkey" => "key", "data" => %{"format" => "event_id_only"}}] =
                        body["devices"]

               {:ok, %{"rejected" => []}}
             end)

    second = message(ctx, "read-before-push")
    {:ok, _} = ClientRooms.receipt(ctx.bob.id, ctx.ref, "m.read.private", second, %{})

    assert :delivered ==
             Pushers.deliver_once(fn _, _ -> flunk("already read event must not be pushed") end)

    assert :delivered ==
             Pushers.deliver_once(fn _, %{"notification" => body} ->
               assert body["counts"]["unread"] == 0
               refute Map.has_key?(body, "event_id")
               {:ok, %{"rejected" => []}}
             end)

    {:ok, _} = ClientStore.delete_devices(ctx.bob.id, ["B"])
    assert Pushers.list(ctx.bob.id) == %{"pushers" => []}
    assert :idle == Pushers.deliver_once()
  end

  test "pusher append and removal preserve account ownership, rejected keys and unsafe URLs are handled",
       ctx do
    {:ok, _} = Pushers.set(ctx.alice.id, "A", pusher())
    {:ok, _} = Pushers.set(ctx.bob.id, "B", Map.put(pusher(), "append", true))
    assert length(Pushers.list(ctx.alice.id)["pushers"]) == 1
    {:ok, _} = Pushers.set(ctx.bob.id, "B", pusher())
    assert Pushers.list(ctx.alice.id)["pushers"] == []

    for url <- [
          "http://push.example/notify",
          "https://user:pass@push.example/",
          "javascript:alert(1)"
        ] do
      assert {:error, :invalid_param} =
               Pushers.set(ctx.bob.id, "B", put_in(pusher(), ["data", "url"], url))
    end

    assert {:error, :blocked_address} = Pushers.request("https://127.0.0.1/notify", %{})
    message(ctx, "rejected")
    assert :delivered == Pushers.deliver_once(fn _, _ -> {:ok, %{"rejected" => ["key"]}} end)
    assert Pushers.list(ctx.bob.id)["pushers"] == []
  end
end
