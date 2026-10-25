defmodule LakehouseMatrix.RoomResetTest do
  use LakehouseMatrix.DataCase, async: false
  alias LakehouseIam.Schema.{AppGrant, Grant, Principal, Resource}

  alias LakehouseMatrix.{
    ClientRooms,
    ClientStore,
    Cursor,
    Fixtures,
    Identity,
    KeyBackups,
    Media,
    RoomReset
  }

  alias LakehouseMatrix.Protocol.Graph

  setup do
    root = Path.join(System.tmp_dir!(), "matrix-room-reset-#{System.unique_integer([:positive])}")
    keys = [:native_event_graph, :signing_key, :signing_key_id, :media_root, :media_store]
    old = Map.new(keys, &{&1, Application.get_env(:lakehouse_matrix, &1)})
    Application.put_env(:lakehouse_matrix, :native_event_graph, true)

    Application.put_env(
      :lakehouse_matrix,
      :signing_key,
      Base.encode64(<<0::256>>, padding: false)
    )

    Application.put_env(:lakehouse_matrix, :signing_key_id, "ed25519:test")
    Application.put_env(:lakehouse_matrix, :media_root, root)
    Application.put_env(:lakehouse_matrix, :media_store, LakehouseMatrix.Media.Store.Local)

    on_exit(fn ->
      File.rm_rf(root)

      for {key, value} <- old do
        if is_nil(value),
          do: Application.delete_env(:lakehouse_matrix, key),
          else: Application.put_env(:lakehouse_matrix, key, value)
      end
    end)

    alice = Fixtures.user_fixture("alice")
    {:ok, %{"room_id" => ref}} = ClientRooms.create(alice.id, %{})
    %{alice: alice, ref: ref}
  end

  test "reset is domain-bound, invalidates old cursors and removes only room-scoped data", ctx do
    {:ok, room} = Identity.parse_room_id(ctx.ref)
    {:ok, session} = ClientStore.login(ctx.alice.username, "password123", %{"device_id" => "D"})

    selected =
      %AppGrant{}
      |> AppGrant.changeset(%{
        principal_id: ctx.alice.id,
        app_origin: "https://river.example",
        scopes: ["chats.read"],
        room_mode: :selected,
        room_ids: [room]
      })
      |> Repo.insert!()

    all =
      %AppGrant{}
      |> AppGrant.changeset(%{
        principal_id: ctx.alice.id,
        app_origin: "https://other.example",
        scopes: ["chats.read"],
        room_mode: :all
      })
      |> Repo.insert!()

    resource =
      Repo.get_by(Resource, arn: Identity.resource_arn(room)) ||
        Repo.insert!(Resource.changeset(%Resource{}, %{arn: Identity.resource_arn(room)}))

    {:ok, _} = LakehouseIam.IAM.assign_role(ctx.alice.id, "room_admin", resource.arn)

    {:ok, _} =
      ClientStore.put_data(ctx.alice.id, "", "m.secret_storage.default_key", %{
        "key" => "encrypted-key-id"
      })

    {:ok, _} =
      ClientStore.put_data(ctx.alice.id, "", "m.direct", %{Identity.user_id("bob") => [ctx.ref]})

    {:ok, _} =
      ClientStore.put_data(ctx.alice.id, room, "m.tag", %{"tags" => %{"m.favourite" => %{}}})

    {:ok, _} =
      ClientStore.put_data(ctx.alice.id, "", "m.push_rules", %{
        "global" => %{
          "room" => [%{"rule_id" => ctx.ref}],
          "override" => [%{"rule_id" => "keep-global"}]
        }
      })

    {:ok, backup} =
      KeyBackups.create(ctx.alice.id, %{
        "algorithm" => "m.megolm_backup.v1.curve25519-aes-sha2",
        "auth_data" => %{"public_key" => Base.encode64(<<1::256>>, padding: false)}
      })

    {:ok, upload} = Media.upload(ctx.alice.id, "preserve uploaded bytes")

    Repo.insert_all("matrix_cross_signing", [
      %{
        principal_id: ClientStore.dump_id(ctx.alice.id),
        usage: "master",
        key: %{"keys" => %{"ed25519:test" => "opaque-public-key"}}
      }
    ])

    {:ok, _} =
      ClientRooms.send(ctx.alice.id, "D", ctx.ref, "m.room.message", "old-request", %{
        "body" => "reset history"
      })

    {:ok, _} =
      ClientStore.send_to_device(ctx.alice.id, "D", "alice", "m.test", "keep-request", %{
        Identity.user_id("alice") => %{"D" => %{"encrypted" => "keep"}}
      })

    high = ClientStore.position()
    cursor = Cursor.encode("sync", ctx.alice.id, "D", high)
    assert RoomReset.plan()["rooms"] == 1
    assert {:error, :wrong_server} = RoomReset.run("different.example")
    assert Graph.room(room)
    assert {:ok, stats} = RoomReset.run(Identity.homeserver_domain())
    assert stats["rooms_after"] == 0
    refute Graph.room(room)
    assert ClientStore.position() > high
    assert {:error, :invalid_cursor} = Cursor.decode(cursor, "sync", ctx.alice.id, "D")

    assert {:ok, _} =
             Cursor.decode(
               Cursor.encode("sync", ctx.alice.id, "D", ClientStore.position()),
               "sync",
               ctx.alice.id,
               "D"
             )

    assert ClientStore.authenticate(session["access_token"]) == :error
    assert [%{device_id: "D"}] = ClientStore.devices(ctx.alice.id)
    assert Repo.get!(Principal, ctx.alice.id).active
    assert LakehouseIam.Accounts.password_valid?("alice", "password123")
    assert Repo.get!(AppGrant, selected.id).room_mode == :selected
    assert Repo.get!(AppGrant, selected.id).room_ids == []
    assert Repo.get!(AppGrant, all.id).room_mode == :all
    refute Repo.get(Resource, resource.id)
    refute Repo.exists?(from g in Grant, where: g.resource_id == ^resource.id)

    assert Repo.exists?(
             from g in Grant, where: g.principal_id == ^ctx.alice.id and is_nil(g.resource_id)
           )

    assert ClientStore.get_data(ctx.alice.id, "", "m.secret_storage.default_key") == %{
             "key" => "encrypted-key-id"
           }

    assert ClientStore.get_data(ctx.alice.id, "", "m.direct") == %{}
    assert ClientStore.get_data(ctx.alice.id, room, "m.tag") == nil

    assert ClientStore.get_data(ctx.alice.id, "", "m.push_rules")["global"] == %{
             "room" => [],
             "override" => [%{"rule_id" => "keep-global"}]
           }

    assert {:ok, %{"version" => version}} = KeyBackups.version(ctx.alice.id)
    assert version == backup["version"]
    assert Repo.aggregate(from(k in "matrix_cross_signing"), :count) == 1
    assert Repo.exists?(from t in "matrix_transactions", where: t.scope == "to_device")
    refute Repo.exists?(from t in "matrix_transactions", where: t.scope == ^("send:" <> room))
    assert Repo.aggregate(from(t in "matrix_to_device"), :count) == 1

    assert {:ok, %{body: "preserve uploaded bytes"}} =
             Media.download(ctx.alice.id, Identity.homeserver_domain(), upload.media_id)

    assert {:ok, %{"room_id" => fresh}} = ClientRooms.create(ctx.alice.id, %{})
    refute fresh == ctx.ref

    assert {:ok, %{"access_token" => _}} =
             ClientStore.login("alice", "password123", %{"device_id" => "D"})

    assert {:ok, _} =
             ClientRooms.send(ctx.alice.id, "D", fresh, "m.room.message", "new-request", %{
               "body" => "new native history"
             })
  end
end
