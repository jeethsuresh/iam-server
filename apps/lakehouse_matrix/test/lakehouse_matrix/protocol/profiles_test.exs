defmodule LakehouseMatrix.ClientProfilesTest do
  use LakehouseMatrix.DataCase, async: false
  alias LakehouseMatrix.{ClientContext, ClientProfiles, ClientRooms, Fixtures, Identity, Matrix}

  setup do
    settings = [:native_event_graph, :signing_key, :signing_key_id, :federation_requester]
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
    outsider = Fixtures.user_fixture("outsider")
    {:ok, %{"room_id" => ref}} = ClientRooms.create(alice.id, %{"preset" => "public_chat"})
    {:ok, _} = Matrix.join_room(bob.id, ref)
    %{alice: alice, bob: bob, outsider: outsider, ref: ref, user: Identity.user_id("alice")}
  end

  test "profile changes update joined room memberships and cannot change another user's profile",
       ctx do
    assert {:ok, %{}} = ClientProfiles.put(ctx.alice.id, ctx.user, "displayname", "Alicia")

    assert {:ok, %{}} =
             ClientProfiles.put(
               ctx.alice.id,
               ctx.user,
               "avatar_url",
               "mxc://example.org/avatar_id"
             )

    assert {:ok, %{"displayname" => "Alicia", "avatar_url" => "mxc://example.org/avatar_id"}} =
             ClientProfiles.get(ctx.user)

    assert {:ok, %{"chunk" => members}} = ClientContext.members(ctx.bob.id, "B", ctx.ref, %{})

    assert Enum.any?(
             members,
             &(&1["state_key"] == ctx.user and &1["content"]["displayname"] == "Alicia" and
                 &1["content"]["avatar_url"] == "mxc://example.org/avatar_id")
           )

    assert {:error, :forbidden} =
             ClientProfiles.put(ctx.bob.id, ctx.user, "displayname", "Impersonation")

    assert {:error, :invalid_param} =
             ClientProfiles.put(
               ctx.alice.id,
               ctx.user,
               "avatar_url",
               "mxc://example.org/../private"
             )

    assert {:ok, %{}} = ClientProfiles.put(ctx.alice.id, ctx.user, "displayname", nil)
    assert {:ok, %{"displayname" => nil}} = ClientProfiles.get(ctx.user)
  end

  test "directory searches only shared-room users, and remote profile replies expose only profile fields",
       ctx do
    {:ok, _} = ClientProfiles.put(ctx.alice.id, ctx.user, "displayname", "Alicia")

    assert {:ok, %{"results" => [%{"user_id" => user}]}} =
             ClientProfiles.search(ctx.bob.id, %{"search_term" => "Alicia"})

    assert user == ctx.user

    assert {:ok, %{"results" => []}} =
             ClientProfiles.search(ctx.outsider.id, %{"search_term" => "Alicia"})

    Application.put_env(:lakehouse_matrix, :federation_requester, fn :get,
                                                                     "remote.org",
                                                                     path,
                                                                     nil ->
      refute Repo.in_transaction?()
      assert URI.decode_query(URI.parse(path).query)["user_id"] == "@remote:remote.org"
      {:ok, %{"displayname" => "Remote", "avatar_url" => nil, "other_data" => "omit"}}
    end)

    assert {:ok, %{"displayname" => "Remote", "avatar_url" => nil}} =
             ClientProfiles.get("@remote:remote.org")
  end
end
