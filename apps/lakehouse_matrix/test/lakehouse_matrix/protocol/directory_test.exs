defmodule LakehouseMatrix.DirectoryTest do
  use LakehouseMatrix.DataCase, async: false
  alias LakehouseMatrix.{ClientRooms, Directory, Fixtures, Identity, Matrix}
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
      for {k, v} <- old do
        if is_nil(v),
          do: Application.delete_env(:lakehouse_matrix, k),
          else: Application.put_env(:lakehouse_matrix, k, v)
      end
    end)

    %{alice: Fixtures.user_fixture("alice"), bob: Fixtures.user_fixture("bob")}
  end

  test "aliases resolve, join and delete without resurrecting the creation alias", ctx do
    {:ok, %{"room_id" => ref}} =
      ClientRooms.create(ctx.alice.id, %{
        "room_alias_name" => "created",
        "preset" => "public_chat"
      })

    alias_ref = Identity.room_alias("created")
    assert {:ok, %{"room_id" => ^ref}} = Directory.resolve(alias_ref)
    assert {:ok, _} = Matrix.join_room(ctx.bob.id, alias_ref)
    extra = Identity.room_alias("another")
    assert {:ok, %{}} = Directory.put(ctx.bob.id, extra, ref)
    assert {:error, :alias_in_use} = Directory.put(ctx.alice.id, extra, ref)
    assert {:ok, %{"aliases" => aliases}} = Directory.aliases(ctx.bob.id, ref)
    assert Enum.sort(aliases) == Enum.sort([extra, alias_ref])
    assert {:error, :forbidden} = Directory.delete(ctx.bob.id, alias_ref)
    assert {:ok, %{}} = Directory.delete(ctx.alice.id, alias_ref)
    assert {:error, :not_found} = Directory.resolve(alias_ref)
    assert {:ok, _} = Directory.delete(ctx.bob.id, extra)
    assert {:ok, %{"aliases" => []}} = Directory.aliases(ctx.alice.id, ref)

    assert {:error, :invalid_param} =
             Directory.put(ctx.alice.id, Identity.room_alias("bad\x00"), ref)

    assert {:error, :invalid_param} = ClientRooms.create(ctx.alice.id, %{"room_alias_name" => 1})

    assert {:error, :invalid_param} =
             ClientRooms.create(ctx.alice.id, %{"room_alias_name" => String.duplicate("a", 255)})
  end

  test "publication is explicit, permission checked, filtered, cursor bound, and ACL aware",
       ctx do
    {:ok, %{"room_id" => private}} =
      ClientRooms.create(ctx.alice.id, %{"name" => "Unlisted", "preset" => "public_chat"})

    {:ok, %{"room_id" => public}} =
      ClientRooms.create(ctx.alice.id, %{
        "name" => "Public",
        "visibility" => "public",
        "preset" => "public_chat"
      })

    {:ok, %{"room_id" => space}} =
      ClientRooms.create(ctx.alice.id, %{
        "name" => "Space",
        "visibility" => "public",
        "creation_content" => %{"type" => "m.space"}
      })

    assert {:ok, %{"chunk" => rooms}} = Directory.public_rooms(%{})
    assert Enum.sort(Enum.map(rooms, & &1["room_id"])) == Enum.sort([public, space])

    assert {:ok, %{"chunk" => [%{"room_id" => ^public}]}} =
             Directory.public_rooms(%{
               "filter" => %{"generic_search_term" => "PUBLIC", "room_types" => [nil]}
             })

    assert {:ok, %{"chunk" => [%{"room_id" => ^space}]}} =
             Directory.public_rooms(%{"filter" => %{"room_types" => ["m.space"]}})

    assert {:ok, first} = Directory.public_rooms(%{"limit" => 1})
    assert {:ok, second} = Directory.public_rooms(%{"limit" => 1, "since" => first["next_batch"]})
    refute hd(first["chunk"])["room_id"] == hd(second["chunk"])["room_id"]

    assert {:error, :invalid_cursor} =
             Directory.public_rooms(%{
               "since" => first["next_batch"],
               "filter" => %{"room_types" => [nil]}
             })

    assert {:ok, _} = Matrix.join_room(ctx.bob.id, private)
    assert {:error, :forbidden} = Directory.visibility(ctx.bob.id, private, "public")
    assert {:ok, _} = Directory.visibility(ctx.alice.id, private, "public")
    assert {:ok, %{"visibility" => "public"}} = Directory.visibility(private)
    {:ok, room} = Identity.parse_room_id(public)

    {:ok, _} =
      Graph.send(
        room,
        Identity.user_id("alice"),
        "m.room.server_acl",
        %{"allow" => ["*"], "deny" => ["blocked.org"]},
        ""
      )

    assert {:ok, %{"chunk" => filtered}} = Directory.public_rooms(%{}, "blocked.org")
    refute Enum.any?(filtered, &(&1["room_id"] == public))
  end

  test "native ban, unban and kick use the signed room authorization rules", ctx do
    {:ok, %{"room_id" => ref}} = ClientRooms.create(ctx.alice.id, %{"preset" => "public_chat"})
    {:ok, _} = Matrix.join_room(ctx.bob.id, ref)

    assert {:error, :forbidden} =
             ClientRooms.moderate(ctx.bob.id, ref, "ban", Identity.user_id("alice"))

    assert {:ok, %{}} =
             ClientRooms.moderate(ctx.alice.id, ref, "ban", Identity.user_id("bob"), "reason")

    assert {:error, _} = Matrix.join_room(ctx.bob.id, ref)
    assert {:ok, %{}} = ClientRooms.moderate(ctx.alice.id, ref, "unban", Identity.user_id("bob"))
    assert {:ok, _} = Matrix.join_room(ctx.bob.id, ref)
    assert {:ok, %{}} = ClientRooms.moderate(ctx.alice.id, ref, "kick", Identity.user_id("bob"))

    assert {:error, :not_found} =
             ClientRooms.moderate(ctx.alice.id, ref, "kick", Identity.user_id("bob"))

    assert {:ok, %{}} = ClientRooms.moderate(ctx.alice.id, ref, "ban", "@remote:elsewhere.org")
  end
end
