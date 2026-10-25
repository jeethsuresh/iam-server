defmodule LakehouseMatrix.Protocol.EncryptionIdentityTest do
  use LakehouseMatrix.DataCase, async: false
  alias LakehouseMatrix.{ClientKeys, ClientStore, ClientUia, CrossSigning, Fixtures}
  alias LakehouseMatrix.Federation.{DeviceKeys, Signing}
  @master <<10::256>>
  @self <<11::256>>
  @user <<12::256>>
  @device <<13::256>>

  setup do
    alice = Fixtures.user_fixture("cryptoalice")
    {:ok, session} = ClientStore.login(alice.username, "password123", %{"device_id" => "A"})
    %{alice: alice, mxid: session["user_id"]}
  end

  defp key(seed, usage, user) do
    public = Signing.public_key(seed) |> Base.encode64(padding: false)
    %{"user_id" => user, "usage" => [usage], "keys" => %{("ed25519:" <> public) => public}}
  end

  defp signed(key, seed, user),
    do:
      Signing.sign(
        key,
        seed,
        "ed25519:" <> Base.encode64(Signing.public_key(seed), padding: false),
        user
      )

  defp device(user),
    do: %{
      "user_id" => user,
      "device_id" => "A",
      "algorithms" => ["m.olm.v1.curve25519-aes-sha2", "m.megolm.v1.aes-sha2"],
      "keys" => %{"ed25519:A" => Base.encode64(Signing.public_key(@device), padding: false)}
    }

  defp identity(user),
    do: %{
      "master_key" => key(@master, "master", user),
      "self_signing_key" => signed(key(@self, "self_signing", user), @master, user),
      "user_signing_key" => signed(key(@user, "user_signing", user), @master, user)
    }

  test "first cross-signing identity is free to upload, retries are idempotent and resets require reauthentication",
       ctx do
    initial = identity(ctx.mxid)
    assert {:ok, %{}} = CrossSigning.upload(ctx.alice.id, initial)
    assert {:ok, %{}} = CrossSigning.upload(ctx.alice.id, initial)
    assert {:ok, own} = ClientKeys.query(ctx.alice.id, %{ctx.mxid => []})
    assert own["master_keys"][ctx.mxid] == initial["master_key"]
    assert own["user_signing_keys"][ctx.mxid] == initial["user_signing_key"]
    assert {:ok, public} = DeviceKeys.query(%{ctx.mxid => []})
    refute Map.has_key?(public["user_signing_keys"], ctx.mxid)
    replacement = %{"master_key" => key(<<14::256>>, "master", ctx.mxid)}
    assert {:error, :reauth_required} = CrossSigning.upload(ctx.alice.id, replacement)
    assert {:ok, %{}} = CrossSigning.upload(ctx.alice.id, replacement, true)
    assert CrossSigning.keys(ctx.alice.id)["self_signing"] == nil
  end

  test "a self-signing key must be signed by the uploaded master", ctx do
    params = identity(ctx.mxid) |> put_in(["self_signing_key", "signatures", ctx.mxid], %{})
    assert {:error, :invalid_signature} = CrossSigning.upload(ctx.alice.id, params)
    assert CrossSigning.keys(ctx.alice.id) == %{}
  end

  test "UIA binds ordinary JSON numeric values without requiring PDU canonical JSON", ctx do
    body = %{"extra" => %{"number" => 0.5, "other" => [1, true]}}

    {:error, {:uia, challenge}} =
      ClientUia.perform(ctx.alice.id, "A", "numeric-json", body, fn ->
        flunk("not authenticated")
      end)

    auth = %{
      "type" => "m.login.password",
      "user" => "cryptoalice",
      "password" => "password123",
      "session" => challenge["session"]
    }

    authorized = Map.put(body, "auth", auth)

    assert {:ok, %{}} =
             ClientUia.perform(ctx.alice.id, "A", "numeric-json", authorized, fn -> {:ok, %{}} end)
  end

  test "uploaded device signatures are verified and cannot change the key object", ctx do
    assert {:ok, _} =
             ClientKeys.upload(ctx.alice.id, "A", ctx.alice.username, %{
               "device_keys" => device(ctx.mxid)
             })

    assert {:ok, _} = CrossSigning.upload(ctx.alice.id, identity(ctx.mxid))
    signed = signed(device(ctx.mxid), @self, ctx.mxid)

    assert {:ok, %{"failures" => %{}}} =
             CrossSigning.signatures(ctx.alice.id, %{ctx.mxid => %{"A" => signed}})

    assert {:ok, queried} = DeviceKeys.query(%{ctx.mxid => []})

    assert CrossSigning.signed_by?(
             queried["device_keys"][ctx.mxid]["A"],
             key(@self, "self_signing", ctx.mxid),
             ctx.mxid
           )

    tampered = put_in(signed, ["keys", "ed25519:A"], "different")

    assert {:ok, %{"failures" => failures}} =
             CrossSigning.signatures(ctx.alice.id, %{ctx.mxid => %{"A" => tampered}})

    assert failures[ctx.mxid]["A"]["errcode"] == "M_INVALID_SIGNATURE"
  end

  test "UIA sessions are bound to the device and request and are consumed once", ctx do
    body = %{"devices" => ["A"]}

    assert {:error, {:uia, challenge}} =
             ClientUia.perform(ctx.alice.id, "A", "delete", body, fn ->
               flunk("not authenticated")
             end)

    auth = %{
      "type" => "m.login.password",
      "session" => challenge["session"],
      "identifier" => %{"type" => "m.id.user", "user" => ctx.mxid},
      "password" => "password123"
    }

    authorized = Map.put(body, "auth", auth)

    assert {:error, {:uia, _}} =
             ClientUia.perform(ctx.alice.id, "B", "delete", authorized, fn ->
               flunk("wrong device")
             end)

    assert {:error, {:uia, _}} =
             ClientUia.perform(
               ctx.alice.id,
               "A",
               "delete",
               Map.put(authorized, "devices", []),
               fn -> flunk("wrong request") end
             )

    assert {:ok, %{}} =
             ClientUia.perform(ctx.alice.id, "A", "delete", authorized, fn -> {:ok, %{}} end)

    assert {:error, {:uia, _}} =
             ClientUia.perform(ctx.alice.id, "A", "delete", authorized, fn -> flunk("replay") end)
  end

  test "device revocation removes keys, queued messages and access tokens and advances device-list history",
       ctx do
    assert {:ok, session} =
             ClientStore.login(ctx.alice.username, "password123", %{"device_id" => "B"})

    assert {:ok, _} =
             ClientKeys.upload(ctx.alice.id, "B", ctx.alice.username, %{
               "one_time_keys" => %{"signed_curve25519:one" => %{"key" => "opaque"}}
             })

    assert {:ok, _} =
             ClientStore.send_to_device(
               ctx.alice.id,
               "A",
               ctx.alice.username,
               "m.room.encrypted",
               "local",
               %{ctx.mxid => %{"B" => %{"ciphertext" => "opaque"}}}
             )

    before = ClientStore.position()
    assert {:ok, _} = ClientStore.delete_devices(ctx.alice.id, ["B"])
    assert :error = ClientStore.authenticate(session["access_token"])
    assert ClientKeys.counts(ctx.alice.id, "B") == %{}
    assert ClientStore.to_device(ctx.alice.id, "B", 0, ClientStore.position()) == []

    assert Repo.exists?(
             from c in "matrix_device_changes",
               where: c.user_id == ^ctx.mxid and c.stream_id > ^before
           )
  end

  test "remote to-device messages are durably queued once with their original opaque ciphertext",
       ctx do
    messages = %{
      "@bob:remote.org" => %{
        "B" => %{"algorithm" => "m.olm.v1.curve25519-aes-sha2", "ciphertext" => "opaque"}
      }
    }

    assert {:ok, %{}} =
             ClientStore.send_to_device(
               ctx.alice.id,
               "A",
               ctx.alice.username,
               "m.room.encrypted",
               "remote",
               messages
             )

    assert {:ok, %{}} =
             ClientStore.send_to_device(
               ctx.alice.id,
               "A",
               ctx.alice.username,
               "m.room.encrypted",
               "remote",
               messages
             )

    assert [payload] =
             Repo.all(
               from o in "matrix_federation_outbox",
                 where: o.destination == "remote.org",
                 select: o.payload
             )

    assert [%{"edu_type" => "m.direct_to_device", "content" => content}] = payload["edus"]
    assert content["sender"] == ctx.mxid
    assert content["messages"] == messages
  end

  test "remote key responses cannot inject another user's keys or expose user-signing keys",
       _ctx do
    bob = "@bob:remote.org"
    evil = "@mallory:evil.org"

    request = fn :post, "remote.org", _, %{"device_keys" => %{^bob => []}} ->
      {:ok,
       %{
         "device_keys" => %{
           bob => %{
             "B" => %{"user_id" => evil, "device_id" => "B", "keys" => %{}, "algorithms" => []}
           }
         },
         "master_keys" => %{evil => key(@master, "master", evil)},
         "user_signing_keys" => %{bob => key(@user, "user_signing", bob)}
       }}
    end

    result = DeviceKeys.remote(%{bob => []}, "query", request)
    assert result["device_keys"] == %{bob => %{}}
    assert result["master_keys"] == %{}
    refute Map.has_key?(result, "user_signing_keys")
  end
end
