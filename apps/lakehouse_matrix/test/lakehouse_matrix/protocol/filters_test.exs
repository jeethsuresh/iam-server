defmodule LakehouseMatrix.ClientFiltersTest do
  use LakehouseMatrix.DataCase, async: false
  alias LakehouseMatrix.{ClientProfiles, ClientRooms, ClientSync, Fixtures, Identity, Matrix}

  setup do
    settings = [:native_event_graph, :signing_key, :signing_key_id]
    old = Map.new(settings, &{&1, Application.get_env(:lakehouse_matrix, &1)})
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
    {:ok, %{"room_id" => other}} = ClientRooms.create(alice.id, %{})
    {:ok, _} = Matrix.join_room(bob.id, ref)
    %{alice: alice, bob: bob, ref: ref, other: other}
  end

  test "timeline filtering happens before the limit and supports wildcards anywhere in a type",
       ctx do
    {:ok, before} = ClientSync.sync(ctx.alice.id, "A", %{})

    {:ok, match} =
      ClientRooms.send(ctx.alice.id, "A", ctx.ref, "m.custom.match", "matched", %{
        "body" => "keep me"
      })

    for n <- 1..5,
        do:
          ClientRooms.send(ctx.alice.id, "A", ctx.ref, "m.custom.other", "ignored#{n}", %{
            "body" => "ignored"
          })

    filter =
      Jason.encode!(%{"room" => %{"timeline" => %{"limit" => 1, "types" => ["m.*.match"]}}})

    assert {:ok, sync} =
             ClientSync.sync(ctx.alice.id, "A", %{
               "since" => before["next_batch"],
               "filter" => filter
             })

    assert Enum.map(
             get_in(sync, ["rooms", "join", ctx.ref, "timeline", "events"]),
             & &1["event_id"]
           ) == [match["event_id"]]

    {:ok, literal} = ClientRooms.send(ctx.alice.id, "A", ctx.ref, "m.literal_%", "literal", %{})
    {:ok, _} = ClientRooms.send(ctx.alice.id, "A", ctx.ref, "m.literalXX", "nearby", %{})
    literal_filter = Jason.encode!(%{"room" => %{"timeline" => %{"types" => ["m.literal_%"]}}})
    assert {:ok, literal_sync} = ClientSync.sync(ctx.alice.id, "A", %{"filter" => literal_filter})

    assert Enum.map(
             get_in(literal_sync, ["rooms", "join", ctx.ref, "timeline", "events"]),
             & &1["event_id"]
           ) == [literal["event_id"]]
  end

  test "ignored users stop timelines and invitations immediately while state continues to sync",
       ctx do
    alias LakehouseMatrix.{ClientHistory, ClientStore, SlidingSync}
    {:ok, before} = ClientSync.sync(ctx.bob.id, "B", %{})

    {:ok, _} =
      ClientStore.put_data(ctx.bob.id, "", "m.ignored_user_list", %{
        "ignored_users" => %{Identity.user_id("alice") => %{}}
      })

    {:ok, hidden} =
      ClientRooms.send(ctx.alice.id, "A", ctx.ref, "m.room.message", "ignored", %{
        "body" => "ignored sender"
      })

    {:ok, _} =
      ClientRooms.put_state(ctx.alice.id, ctx.ref, "m.room.topic", "", %{
        "topic" => "state must arrive"
      })

    {:ok, %{"room_id" => invitation}} =
      ClientRooms.create(ctx.alice.id, %{"invite" => [Identity.user_id("bob")]})

    assert {:ok, ignored} =
             ClientSync.sync(ctx.bob.id, "B", %{
               "since" => before["next_batch"],
               "use_state_after" => true
             })

    payload = ignored["rooms"]["join"][ctx.ref]
    refute Enum.any?(payload["timeline"]["events"], &(&1["event_id"] == hidden["event_id"]))

    assert Enum.any?(
             payload["state_after"]["events"],
             &(&1["type"] == "m.room.topic" and &1["content"]["topic"] == "state must arrive")
           )

    refute Map.has_key?(ignored["rooms"]["invite"], invitation)

    assert {:ok, sliding} =
             SlidingSync.sync(ctx.bob.id, "B", %{
               "lists" => %{"all" => %{"range" => [0, 20], "timeline_limit" => 10}}
             })

    refute Map.has_key?(sliding["rooms"], invitation)

    refute Enum.any?(
             sliding["rooms"][ctx.ref]["timeline"],
             &(&1["event_id"] == hidden["event_id"])
           )

    {:ok, local} = Identity.parse_room_id(ctx.ref)
    assert {:ok, history} = ClientHistory.page(ctx.bob.id, "B", local, %{})
    refute Enum.any?(history["chunk"], &(&1["event_id"] == hidden["event_id"]))

    {:ok, _} =
      ClientStore.put_data(ctx.bob.id, "", "m.ignored_user_list", %{"ignored_users" => %{}})

    assert {:ok, resumed} = ClientSync.sync(ctx.bob.id, "B", %{"since" => ignored["next_batch"]})

    refute Enum.any?(
             get_in(resumed, ["rooms", "join", ctx.ref, "timeline", "events"]) || [],
             &(&1["event_id"] == hidden["event_id"])
           )

    assert {:ok, fresh} = ClientSync.sync(ctx.bob.id, "B", %{})

    assert Enum.any?(
             fresh["rooms"]["join"][ctx.ref]["timeline"]["events"],
             &(&1["event_id"] == hidden["event_id"])
           )

    assert Map.has_key?(fresh["rooms"]["invite"], invitation)
  end

  test "room filters, URL filtering and federation event format are honored", ctx do
    {:ok, plain} =
      ClientRooms.send(ctx.alice.id, "A", ctx.ref, "m.room.message", "plain", %{"body" => "plain"})

    {:ok, _} =
      ClientRooms.send(ctx.alice.id, "A", ctx.ref, "m.room.message", "file", %{
        "url" => "mxc://example.org/file",
        "body" => "file"
      })

    filter = %{
      "room" => %{
        "rooms" => [ctx.ref],
        "timeline" => %{"types" => ["m.room.message"], "contains_url" => false}
      },
      "presence" => %{"types" => []}
    }

    assert {:ok, sync} = ClientSync.sync(ctx.alice.id, "A", %{"filter" => Jason.encode!(filter)})
    assert Map.keys(sync["rooms"]["join"]) == [ctx.ref]

    assert Enum.map(
             get_in(sync, ["rooms", "join", ctx.ref, "timeline", "events"]),
             & &1["event_id"]
           ) == [plain["event_id"]]

    assert sync["presence"]["events"] == []
    excluded = put_in(filter, ["room", "not_rooms"], [ctx.ref])

    assert {:ok, excluded_sync} =
             ClientSync.sync(ctx.alice.id, "A", %{"filter" => Jason.encode!(excluded)})

    assert excluded_sync["rooms"]["join"] == %{}

    assert {:ok, raw} =
             ClientSync.sync(ctx.alice.id, "A", %{
               "filter" => Jason.encode!(Map.put(filter, "event_format", "federation"))
             })

    assert [%{"auth_events" => _, "hashes" => _, "signatures" => _}] =
             get_in(raw, ["rooms", "join", ctx.ref, "timeline", "events"])

    assert {:error, :invalid_param} =
             ClientSync.sync(ctx.alice.id, "A", %{"filter" => Jason.encode!(%{"presence" => []})})
  end

  test "classic sync retains profile changes removed from the filtered timeline and include_leave returns departure history",
       ctx do
    {:ok, before} = ClientSync.sync(ctx.bob.id, "B", %{})

    {:ok, _} =
      ClientRooms.send(ctx.alice.id, "A", ctx.ref, "m.room.message", "message", %{
        "body" => "before profile"
      })

    {:ok, _} =
      ClientProfiles.put(ctx.alice.id, Identity.user_id("alice"), "displayname", "Updated")

    filter = %{"room" => %{"timeline" => %{"types" => ["m.room.message"]}}}

    assert {:ok, sync} =
             ClientSync.sync(ctx.bob.id, "B", %{
               "since" => before["next_batch"],
               "filter" => Jason.encode!(filter)
             })

    assert Enum.any?(
             get_in(sync, ["rooms", "join", ctx.ref, "state", "events"]),
             &(&1["type"] == "m.room.member" and &1["state_key"] == Identity.user_id("alice") and
                 &1["content"]["displayname"] == "Updated")
           )

    {:ok, _} = Matrix.leave_room(ctx.bob.id, ctx.ref)

    assert {:ok, departed} =
             ClientSync.sync(ctx.bob.id, "B", %{
               "filter" => Jason.encode!(put_in(filter, ["room", "include_leave"], true))
             })

    assert get_in(departed, ["rooms", "leave", ctx.ref])
  end
end
