defmodule LakehouseMatrix.ClientSearchTest do
  use LakehouseMatrix.DataCase, async: false

  alias LakehouseMatrix.{
    ClientProfiles,
    ClientRooms,
    ClientSearch,
    ClientStore,
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
    outsider = Fixtures.user_fixture("outsider")
    {:ok, %{"room_id" => ref}} = ClientRooms.create(alice.id, %{"preset" => "public_chat"})
    {:ok, _} = Matrix.join_room(bob.id, ref)
    %{alice: alice, bob: bob, outsider: outsider, ref: ref}
  end

  defp send_text(user, ref, text) do
    {:ok, event} =
      ClientRooms.send(user.id, "D", ref, "m.room.message", Ecto.UUID.generate(), %{
        "msgtype" => "m.text",
        "body" => text
      })

    event["event_id"]
  end

  defp search(user, criteria) do
    {:ok, %{"search_categories" => %{"room_events" => results}}} =
      ClientSearch.search(user.id, "D", %{"search_categories" => %{"room_events" => criteria}})

    results
  end

  test "ranked plaintext search includes rich topics, event context, historic profiles and grouping",
       ctx do
    {:ok, _} =
      ClientProfiles.put(ctx.alice.id, Identity.user_id("alice"), "displayname", "Historic Alice")

    before = send_text(ctx.alice, ctx.ref, "nearby context")
    match = send_text(ctx.alice, ctx.ref, "walking on Mars")
    after_event = send_text(ctx.bob, ctx.ref, "later context")

    {:ok, _} =
      ClientProfiles.put(ctx.alice.id, Identity.user_id("alice"), "displayname", "New Alice")

    results =
      search(ctx.bob, %{
        "search_term" => "walk Mars",
        "event_context" => %{"before_limit" => 1, "after_limit" => 1, "include_profile" => true},
        "include_state" => true,
        "groupings" => %{"group_by" => [%{"key" => "room_id"}, %{"key" => "sender"}]}
      })

    assert [%{"result" => %{"event_id" => ^match}, "rank" => rank, "context" => context}] =
             results["results"]

    assert rank > 0
    assert [%{"event_id" => ^before}] = context["events_before"]
    assert [%{"event_id" => ^after_event}] = context["events_after"]
    assert context["profile_info"][Identity.user_id("alice")]["displayname"] == "Historic Alice"
    assert results["groups"]["room_id"][ctx.ref]["results"] == [match]
    assert results["groups"]["sender"][Identity.user_id("alice")]["results"] == [match]
    assert is_list(results["state"][ctx.ref])
    refute Map.has_key?(results, "next_batch")

    {:ok, %{"event_id" => topic}} =
      ClientRooms.put_state(ctx.alice.id, ctx.ref, "m.room.topic", "", %{
        "m.topic" => [
          %{"mimetype" => "text/plain", "body" => "Orbiting Jupiter"},
          %{"mimetype" => "text/html", "body" => "PrivateMarkup"}
        ]
      })

    assert [%{"result" => %{"event_id" => ^topic}}] =
             search(ctx.bob, %{"search_term" => "orbit Jupiter", "keys" => ["content.topic"]})[
               "results"
             ]

    assert [] = search(ctx.bob, %{"search_term" => "PrivateMarkup"})["results"]
  end

  test "search excludes encrypted rooms, redactions, ignored senders and inaccessible rooms",
       ctx do
    event = send_text(ctx.alice, ctx.ref, "secretword")
    assert [] = search(ctx.outsider, %{"search_term" => "secretword"})["results"]
    assert {:ok, _} = ClientRooms.redact(ctx.alice.id, "D", ctx.ref, event, "redact", %{})
    assert [] = search(ctx.bob, %{"search_term" => "secretword"})["results"]
    send_text(ctx.alice, ctx.ref, "ignoredword")

    {:ok, _} =
      ClientStore.put_data(ctx.bob.id, "", "m.ignored_user_list", %{
        "ignored_users" => %{Identity.user_id("alice") => %{}}
      })

    assert [] = search(ctx.bob, %{"search_term" => "ignoredword"})["results"]

    {:ok, _} =
      ClientStore.put_data(ctx.bob.id, "", "m.ignored_user_list", %{"ignored_users" => %{}})

    assert {:ok, _} =
             ClientRooms.put_state(ctx.alice.id, ctx.ref, "m.room.encryption", "", %{
               "algorithm" => "m.megolm.v1.aes-sha2"
             })

    assert [] = search(ctx.bob, %{"search_term" => "ignoredword"})["results"]
  end

  test "filters precede limits and departed users cannot search later private history", ctx do
    first = send_text(ctx.alice, ctx.ref, "asteroid first")
    send_text(ctx.bob, ctx.ref, "asteroid excluded")

    results =
      search(ctx.bob, %{
        "search_term" => "asteroid",
        "order_by" => "recent",
        "filter" => %{"senders" => [Identity.user_id("alice")], "limit" => 1}
      })

    assert [%{"result" => %{"event_id" => ^first}}] = results["results"]
    {:ok, _} = Matrix.leave_room(ctx.bob.id, ctx.ref)
    send_text(ctx.alice, ctx.ref, "asteroid after departure")

    assert [
             %{"result" => %{"event_id" => ^first}},
             %{"result" => %{"content" => %{"body" => "asteroid excluded"}}}
           ] =
             search(ctx.bob, %{"search_term" => "asteroid"})["results"]
             |> Enum.sort_by(& &1["result"]["sender"])

    {:ok, _} = ClientRooms.forget(ctx.bob.id, ctx.ref)
    assert [] = search(ctx.bob, %{"search_term" => "asteroid"})["results"]
  end

  test "invalid search shapes cannot reach the index", ctx do
    for criteria <- [
          nil,
          [],
          %{},
          %{"search_term" => "x", "filter" => []},
          %{"search_term" => "x", "keys" => ["content.secret"]},
          %{"search_term" => "x", "event_context" => %{"after_limit" => -1}},
          %{"search_term" => "x", "groupings" => %{"group_by" => ["room_id"]}}
        ] do
      assert {:error, :invalid_param} =
               ClientSearch.search(ctx.alice.id, "D", %{
                 "search_categories" => %{"room_events" => criteria}
               })
    end
  end
end
