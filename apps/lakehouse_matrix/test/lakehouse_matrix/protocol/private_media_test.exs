defmodule LakehouseMatrix.PrivateMediaReferencesTest do
  use LakehouseMatrix.DataCase, async: false
  alias LakehouseMatrix.{ClientProfiles, ClientRooms, Fixtures, Identity, Matrix, Media}
  alias LakehouseMatrix.Protocol.Graph

  setup do
    root =
      Path.join(System.tmp_dir!(), "matrix-private-media-#{System.unique_integer([:positive])}")

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
    bob = Fixtures.user_fixture("bob")
    outsider = Fixtures.user_fixture("outsider")

    {:ok, %{"room_id" => ref}} =
      ClientRooms.create(alice.id, %{
        "preset" => "public_chat",
        "creation_content" => %{"m.federate" => false}
      })

    {:ok, _} = Matrix.join_room(bob.id, ref)
    %{alice: alice, bob: bob, outsider: outsider, ref: ref, server: Identity.homeserver_domain()}
  end

  defp send_file(user, ref, uri) do
    ClientRooms.send(user.id, "D", ref, "m.room.message", Ecto.UUID.generate(), %{
      "msgtype" => "m.file",
      "body" => "attachment",
      "url" => uri
    })
  end

  test "UUID text, foreign-server IDs and unauthorized attachments cannot grant private access",
       ctx do
    {:ok, private} = Media.upload(ctx.alice.id, "private bytes")

    {:ok, %{"room_id" => attack}} =
      ClientRooms.create(ctx.outsider.id, %{"preset" => "public_chat"})

    assert {:ok, _} =
             ClientRooms.send(ctx.outsider.id, "D", attack, "m.room.message", "text", %{
               "body" => private.media_id
             })

    assert {:ok, _} = send_file(ctx.outsider, attack, private.content_uri)
    assert {:ok, _} = send_file(ctx.alice, ctx.ref, "mxc://remote.org/" <> private.media_id)
    assert {:error, :forbidden} = Media.download(ctx.outsider.id, ctx.server, private.media_id)
    assert {:error, :forbidden} = Media.download(ctx.bob.id, ctx.server, private.media_id)
    refute Media.get_record(private.media_id).matrix_public
    assert {:ok, %{"event_id" => event}} = send_file(ctx.alice, ctx.ref, private.content_uri)

    assert {:ok, %{body: "private bytes"}} =
             Media.download(ctx.bob.id, ctx.server, private.media_id)

    refute Media.get_record(private.media_id).matrix_public
    assert {:ok, _} = ClientRooms.redact(ctx.alice.id, "D", ctx.ref, event, "redact", %{})
    assert {:error, :forbidden} = Media.download(ctx.bob.id, ctx.server, private.media_id)
    assert {:ok, _} = Media.download(ctx.alice.id, ctx.server, private.media_id)
  end

  test "private media follows history visibility, current state and authorized forwarding", ctx do
    assert {:ok, _} =
             ClientRooms.put_state(ctx.alice.id, ctx.ref, "m.room.history_visibility", "", %{
               "history_visibility" => "joined"
             })

    {:ok, private} = Media.upload(ctx.alice.id, "old attachment")
    {:ok, _} = send_file(ctx.alice, ctx.ref, private.content_uri)
    {:ok, _} = Matrix.join_room(ctx.outsider.id, ctx.ref)
    assert {:error, :forbidden} = Media.download(ctx.outsider.id, ctx.server, private.media_id)
    assert {:ok, _} = Media.download(ctx.bob.id, ctx.server, private.media_id)

    assert {:ok, %{"event_id" => avatar}} =
             ClientRooms.put_state(ctx.alice.id, ctx.ref, "m.room.avatar", "", %{
               "url" => private.content_uri
             })

    assert {:ok, _} = Media.download(ctx.outsider.id, ctx.server, private.media_id)
    refute Media.get_record(private.media_id).matrix_public
    assert {:ok, _} = ClientRooms.put_state(ctx.alice.id, ctx.ref, "m.room.avatar", "", %{})
    # Replacing state does not erase its visible history; redaction removes the old reference.
    assert {:ok, _} = Media.download(ctx.outsider.id, ctx.server, private.media_id)
    assert {:ok, _} = ClientRooms.redact(ctx.alice.id, "D", ctx.ref, avatar, "clear-avatar", %{})
    assert {:error, :forbidden} = Media.download(ctx.outsider.id, ctx.server, private.media_id)

    {:ok, %{"room_id" => next}} =
      ClientRooms.create(ctx.bob.id, %{
        "preset" => "public_chat",
        "creation_content" => %{"m.federate" => false}
      })

    {:ok, _} = Matrix.join_room(ctx.outsider.id, next)
    assert {:ok, _} = send_file(ctx.bob, next, private.content_uri)
    assert {:ok, _} = Media.download(ctx.outsider.id, ctx.server, private.media_id)
    {:ok, %{"room_id" => federated}} = ClientRooms.create(ctx.bob.id, %{})
    assert Graph.room_by_id(federated)
    assert {:ok, _} = send_file(ctx.bob, federated, private.content_uri)
    assert Media.get_record(private.media_id).matrix_public
    assert {:ok, %{body: "old attachment"}} = Media.federation_download(private.media_id)
  end

  test "image-pack assets retain room authorization and arbitrary fields cannot grant media access",
       ctx do
    {:ok, image} = Media.upload(ctx.alice.id, "private pack image")
    {:ok, unrelated} = Media.upload(ctx.alice.id, "unrelated private bytes")

    assert {:ok, pack} =
             ClientRooms.put_state(ctx.alice.id, ctx.ref, "m.room.image_pack", "custom", %{
               "images" => %{"wave" => %{"url" => image.content_uri, "body" => "Wave"}},
               "pack" => %{"display_name" => unrelated.content_uri},
               "unknown" => unrelated.content_uri
             })

    assert {:ok, %{body: "private pack image"}} =
             Media.download(ctx.bob.id, ctx.server, image.media_id)

    assert {:error, :forbidden} = Media.download(ctx.outsider.id, ctx.server, image.media_id)
    assert {:error, :forbidden} = Media.download(ctx.bob.id, ctx.server, unrelated.media_id)
    refute Media.get_record(image.media_id).matrix_public

    assert {:ok, _} =
             ClientRooms.redact(ctx.alice.id, "A", ctx.ref, pack["event_id"], "redact-pack", %{})

    assert {:error, :forbidden} = Media.download(ctx.bob.id, ctx.server, image.media_id)
  end

  test "only a reader can publish a legacy upload through their public profile", ctx do
    {:ok, private} = Media.upload(ctx.alice.id, "private avatar")

    assert {:ok, _} =
             ClientProfiles.put(
               ctx.outsider.id,
               Identity.user_id("outsider"),
               "avatar_url",
               private.content_uri
             )

    refute Media.get_record(private.media_id).matrix_public

    assert {:ok, _} =
             ClientProfiles.put(
               ctx.alice.id,
               Identity.user_id("alice"),
               "avatar_url",
               private.content_uri
             )

    assert Media.get_record(private.media_id).matrix_public
  end
end
