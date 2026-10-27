defmodule LakehouseWeb.RiverSpaceOwnershipTest do
  use LakehouseWeb.ConnCase
  alias LakehouseIam.Apps.Grants
  alias LakehouseMatrix.{ClientRooms, DelegatedGroups, Identity, RiverContent}
  alias LakehouseWeb.MatrixFixtures

  setup tags do
    keys = [:native_event_graph, :signing_key, :signing_key_id]
    previous = Map.new(keys, &{&1, Application.get_env(:lakehouse_matrix, &1)})
    Application.put_env(:lakehouse_matrix, :native_event_graph, tags.native_graph)

    Application.put_env(
      :lakehouse_matrix,
      :signing_key,
      Base.encode64(:binary.copy(<<7>>, 32), padding: false)
    )

    Application.put_env(:lakehouse_matrix, :signing_key_id, "ed25519:test")

    on_exit(fn ->
      for {key, value} <- previous do
        if is_nil(value),
          do: Application.delete_env(:lakehouse_matrix, key),
          else: Application.put_env(:lakehouse_matrix, key, value)
      end
    end)
  end

  for graph <- [false, true] do
    @tag native_graph: graph
    test "entries belong to the space across multiple conversation rooms (native graph: #{graph})" do
      user = MatrixFixtures.user_fixture("spaceowner")
      scopes = ~w(chats.list chats.read chats.write groups.create groups.manage spaces.channels)
      {:ok, grant} = Grants.upsert(user.id, "https://chat.gravitas.cool", scopes, :all)

      {:ok, space} =
        DelegatedGroups.create(grant, %{"name" => "Space", "kind" => "space", "txn_id" => "space"})

      {:ok, %{channels: children}} = DelegatedGroups.channels(grant, space.id)
      assert length(children) == 2

      {:ok, dm} =
        DelegatedGroups.create(grant, %{
          "name" => "Conversation",
          "kind" => "dm",
          "txn_id" => "dm"
        })

      {:ok, group} =
        DelegatedGroups.create(grant, %{"name" => "Group", "kind" => "group", "txn_id" => "group"})

      content = %{"version" => 1, "title" => "Space entry", "body" => "Shared by the space"}
      wire = Identity.room_id(space.id)

      for kind <- ~w(post discussion) do
        type = "cool.gravitas.river.#{kind}.v1"
        assert {:ok, event} = DelegatedGroups.send(grant, space.id, type, kind, content)
        assert event["content"]["space_id"] == wire

        assert {:ok, _} =
                 ClientRooms.send(
                   user.id,
                   "test-device",
                   wire,
                   type,
                   "native-space-#{kind}",
                   content
                 )

        assert {:ok, ^event} = DelegatedGroups.send(grant, space.id, type, kind, content)

        assert {:ok, %{events: entries}} =
                 RiverContent.entries(grant, space.id, %{"kind" => kind})

        assert Enum.any?(entries, &(&1["event_id"] == event["event_id"]))

        assert {:error, :invalid_event} =
                 DelegatedGroups.send(
                   grant,
                   space.id,
                   type,
                   "wrong-#{kind}",
                   Map.put(content, "space_id", Identity.room_id(dm.id))
                 )

        for room <- [dm, group | children] do
          assert {:error, :space_required} =
                   DelegatedGroups.send(grant, room.id, type, "invalid-#{kind}", content)

          assert {:error, :space_required} =
                   RiverContent.entries(grant, room.id, %{"kind" => kind})

          assert {:error, :space_required} =
                   ClientRooms.send(
                     user.id,
                     "test-device",
                     Identity.room_id(room.id),
                     type,
                     "native-#{kind}",
                     content
                   )
        end
      end

      {:ok, tokens} = LakehouseIam.Apps.Tokens.issue(grant)
      path = "/app/v1/spaces/#{space.id}/entries/cool.gravitas.river.post.v1/http-post"

      result =
        build_conn()
        |> put_req_header("authorization", "Bearer " <> tokens.access_token)
        |> put(path, %{"content" => content})
        |> json_response(200)

      assert result["content"]["space_id"] == wire

      list =
        build_conn()
        |> put_req_header("authorization", "Bearer " <> tokens.access_token)
        |> get("/app/v1/spaces/#{space.id}/entries", %{"kind" => "post"})
        |> json_response(200)

      assert Enum.any?(list["events"], &(&1["event_id"] == result["event_id"]))

      forbidden =
        build_conn()
        |> put_req_header("authorization", "Bearer " <> tokens.access_token)
        |> put("/app/v1/spaces/#{dm.id}/entries/cool.gravitas.river.post.v1/no-post", %{
          "content" => content
        })
        |> json_response(400)

      assert forbidden["error"] == "space_required"
    end
  end
end
