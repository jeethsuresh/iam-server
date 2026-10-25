defmodule LakehouseMatrix.Protocol.SpacesTest do
  use LakehouseMatrix.DataCase, async: false
  alias LakehouseMatrix.{ClientRooms, ClientSpaces, Fixtures, Identity, Matrix}
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

  defp room(ctx, name, opts \\ %{}) do
    {:ok, %{"room_id" => ref}} =
      ClientRooms.create(
        ctx.alice.id,
        Map.merge(%{"name" => name, "preset" => "public_chat"}, opts)
      )

    ref
  end

  defp space(ctx, name), do: room(ctx, name, %{"creation_content" => %{"type" => "m.space"}})

  defp edge(ctx, parent, child, order, suggested \\ false) do
    {:ok, _} =
      ClientRooms.put_state(ctx.alice.id, parent, "m.space.child", child, %{
        "via" => [Identity.homeserver_domain()],
        "order" => order,
        "suggested" => suggested
      })
  end

  defp names(response), do: Enum.map(response["rooms"], & &1["name"])

  test "a hierarchy cursor does not preserve access after the root closes", ctx do
    root = space(ctx, "root")
    child = room(ctx, "child")
    edge(ctx, root, child, "a")
    {:ok, first} = ClientSpaces.hierarchy(ctx.bob.id, "B", root, %{"limit" => 1})

    {:ok, _} =
      ClientRooms.put_state(ctx.alice.id, root, "m.room.join_rules", "", %{
        "join_rule" => "invite"
      })

    assert {:error, :forbidden} =
             ClientSpaces.hierarchy(ctx.bob.id, "B", root, %{"from" => first["next_batch"]})
  end

  test "hierarchy follows child order depth-first, filters private children and terminates cycles",
       ctx do
    root = space(ctx, "root")
    branch = space(ctx, "branch")
    nested = room(ctx, "nested")
    leaf = room(ctx, "leaf")
    private = room(ctx, "private", %{"preset" => "private_chat"})
    edge(ctx, root, leaf, "b")
    edge(ctx, root, branch, "a")
    edge(ctx, root, private, "c")
    edge(ctx, branch, nested, "a")
    edge(ctx, branch, root, "b")
    assert {:ok, result} = ClientSpaces.hierarchy(ctx.bob.id, "B", root, %{})
    assert names(result) == ["root", "branch", "nested", "leaf"]
    assert Enum.all?(result["rooms"], &is_list(&1["children_state"]))
    refute result["next_batch"]
    assert {:error, :forbidden} = ClientSpaces.hierarchy(ctx.bob.id, "B", private, %{})
    assert {:ok, shallow} = ClientSpaces.hierarchy(ctx.bob.id, "B", root, %{"max_depth" => 1})
    assert names(shallow) == ["root", "branch", "leaf"]
    assert {:ok, only_root} = ClientSpaces.hierarchy(ctx.bob.id, "B", root, %{"max_depth" => 0})
    assert names(only_root) == ["root"]
  end

  test "pagination binds filters, room, user and device and suggested subtrees remain consistent",
       ctx do
    root = space(ctx, "root")
    branch = space(ctx, "branch")
    leaf = room(ctx, "leaf")
    ignored = room(ctx, "unsuggested")
    edge(ctx, root, branch, "a", true)
    edge(ctx, branch, leaf, "a", true)
    edge(ctx, root, ignored, "b", false)
    params = %{"limit" => 1, "suggested_only" => "true", "max_depth" => 4}
    assert {:ok, first} = ClientSpaces.hierarchy(ctx.alice.id, "A", root, params)
    assert names(first) == ["root"]

    assert {:ok, second} =
             ClientSpaces.hierarchy(ctx.alice.id, "A", root, %{
               "from" => first["next_batch"],
               "limit" => 1
             })

    assert names(second) == ["branch"]

    assert {:ok, third} =
             ClientSpaces.hierarchy(ctx.alice.id, "A", root, %{"from" => second["next_batch"]})

    assert names(third) == ["leaf"]
    refute third["next_batch"]

    for {user, device, ref, extra} <- [
          {ctx.bob.id, "A", root, %{}},
          {ctx.alice.id, "other", root, %{}},
          {ctx.alice.id, "A", branch, %{}},
          {ctx.alice.id, "A", root, %{"suggested_only" => false}},
          {ctx.alice.id, "A", root, %{"max_depth" => 3}}
        ] do
      assert {:error, :invalid_cursor} =
               ClientSpaces.hierarchy(
                 user,
                 device,
                 ref,
                 Map.put(extra, "from", first["next_batch"])
               )
    end
  end

  test "restricted previews check actual user eligibility, and federation checks server ACL and m.federate",
       ctx do
    root = space(ctx, "parent")

    restricted =
      room(ctx, "restricted", %{
        "initial_state" => [
          %{
            "type" => "m.room.join_rules",
            "state_key" => "",
            "content" => %{
              "join_rule" => "restricted",
              "allow" => [%{"type" => "m.room_membership", "room_id" => root}]
            }
          }
        ]
      })

    edge(ctx, root, restricted, "a")
    assert {:ok, before} = ClientSpaces.hierarchy(ctx.bob.id, "B", root, %{})
    assert names(before) == ["parent"]
    {:ok, _} = Matrix.join_room(ctx.bob.id, root)
    assert {:ok, eligible} = ClientSpaces.hierarchy(ctx.bob.id, "B", root, %{})
    assert names(eligible) == ["parent", "restricted"]
    assert {:ok, summary} = ClientSpaces.summary(ctx.bob.id, restricted)
    assert summary["allowed_room_ids"] == [root]
    refute Map.has_key?(summary, "children_state")
    assert {:ok, federation} = ClientSpaces.federation("remote.org", root, %{})
    assert federation["children"] == []
    assert federation["inaccessible_children"] == [restricted]

    local_only =
      room(ctx, "internal", %{
        "creation_content" => %{"type" => "m.space", "m.federate" => false},
        "initial_state" => [
          %{
            "type" => "m.room.history_visibility",
            "state_key" => "",
            "content" => %{"history_visibility" => "world_readable"}
          }
        ]
      })

    assert {:error, :forbidden} = ClientSpaces.federation("remote.org", local_only, %{})

    {:ok, _} =
      ClientRooms.put_state(ctx.alice.id, root, "m.room.server_acl", "", %{
        "allow" => ["*"],
        "deny" => ["remote.org"]
      })

    assert {:error, :forbidden} = ClientSpaces.federation("remote.org", root, %{})
  end

  test "remote previews cache metadata without promoting room state and recheck user eligibility",
       ctx do
    local = space(ctx, "local eligibility")
    root = "!root:remote.org"

    children = [
      {"!public:remote.org", "public"},
      {"!private:remote.org", "invite"},
      {"!restricted:remote.org", "restricted"}
    ]

    request = fn :get, "remote.org", path, nil ->
      refute Repo.in_transaction?()
      Process.put(:space_requests, (Process.get(:space_requests) || 0) + 1)

      ref =
        path
        |> URI.parse()
        |> Map.fetch!(:path)
        |> String.split("/")
        |> List.last()
        |> URI.decode()

      if ref == "!blocked:remote.org", do: flunk("inaccessible child was re-requested")

      rule =
        case List.keyfind(children, ref, 0) do
          nil -> "public"
          {_, value} -> value
        end

      state =
        if ref == root,
          do:
            Enum.map(children ++ [{"!blocked:remote.org", "invite"}], fn {id, _} ->
              %{
                "type" => "m.space.child",
                "state_key" => id,
                "sender" => "@host:remote.org",
                "origin_server_ts" => 1000,
                "content" => %{"via" => ["remote.org"], "order" => id}
              }
            end),
          else: []

      {:ok,
       %{
         "room" => %{
           "room_id" => ref,
           "name" => ref,
           "room_type" => if(ref == root, do: "m.space"),
           "join_rule" => rule,
           "world_readable" => false,
           "num_joined_members" => 1,
           "allowed_room_ids" => [local],
           "children_state" => state
         },
         "children" => [],
         "inaccessible_children" => ["!blocked:remote.org"]
       }}
    end

    assert {:ok, first} =
             ClientSpaces.hierarchy(ctx.bob.id, "B", root, %{}, ["remote.org"], request)

    assert names(first) == [root, "!public:remote.org"]
    requests = Process.get(:space_requests)
    assert requests == 4
    assert Graph.room_by_id(root) == nil
    {:ok, _} = Matrix.join_room(ctx.bob.id, local)

    assert {:ok, second} =
             ClientSpaces.hierarchy(ctx.bob.id, "B", root, %{}, ["remote.org"], request)

    assert Enum.sort(names(second)) ==
             Enum.sort([root, "!public:remote.org", "!restricted:remote.org"])

    assert Process.get(:space_requests) == requests
    assert {:ok, summary} = ClientSpaces.summary(ctx.bob.id, root, ["remote.org"], request)
    assert summary["name"] == root
    refute Map.has_key?(summary, "children_state")
    assert Graph.room_by_id(root) == nil
  end
end
