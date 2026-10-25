defmodule LakehouseMatrix.Federation.KeyringTest do
  use LakehouseMatrix.DataCase, async: false
  alias LakehouseMatrix.Federation.{Keyring, Signing}
  @server "keys.remote.org"
  @old <<1::256>>
  @current <<2::256>>

  defp document(seed, id, until, old \\ %{}) do
    Signing.sign(
      %{
        "server_name" => @server,
        "valid_until_ts" => until,
        "verify_keys" => %{
          id => %{"key" => Base.encode64(Signing.public_key(seed), padding: false)}
        },
        "old_verify_keys" => old
      },
      seed,
      id,
      @server
    )
  end

  test "key documents are cached and historical keys obey their retirement time" do
    now = System.system_time(:millisecond)

    old = %{
      "ed25519:old" => %{
        "key" => Base.encode64(Signing.public_key(@old), padding: false),
        "expired_ts" => now - 10_000
      }
    }

    doc = document(@current, "ed25519:current", now + 60_000, old)

    fetch = fn @server, _ ->
      send(self(), :fetched)
      {:ok, doc}
    end

    assert {:ok, current} = Keyring.key(@server, "ed25519:current", now, fetch)
    assert current == Signing.public_key(@current)
    assert_received :fetched
    assert {:ok, _} = Keyring.key(@server, "ed25519:old", now - 20_000, fetch)
    refute_received :fetched
    assert {:error, :unknown_key} = Keyring.key(@server, "ed25519:old", now, fetch)
  end

  test "an explicit retirement bounds a previously cached current key" do
    now = System.system_time(:millisecond)
    assert :ok = Keyring.remember(@server, document(@old, "ed25519:old", now + 60_000))

    old = %{
      "ed25519:old" => %{
        "key" => Base.encode64(Signing.public_key(@old), padding: false),
        "expired_ts" => now - 1
      }
    }

    assert :ok =
             Keyring.remember(@server, document(@current, "ed25519:current", now + 60_000, old))

    assert {:error, :unavailable} =
             Keyring.key(@server, "ed25519:old", now, fn _, _ -> {:error, :unavailable} end)
  end

  test "a key ID cannot silently be reused for different public material" do
    until = System.system_time(:millisecond) + 60_000
    assert :ok = Keyring.remember(@server, document(@old, "ed25519:same", until))

    assert {:error, :signing_key_reused} =
             Keyring.remember(@server, document(@current, "ed25519:same", until))

    assert {:ok, public} = Keyring.key(@server, "ed25519:same", until - 1)
    assert public == Signing.public_key(@old)
  end

  test "expired, wrong-origin and altered documents cannot seed the key cache" do
    until = System.system_time(:millisecond) + 60_000

    assert {:error, :invalid_key_document} =
             Keyring.remember(@server, document(@current, "ed25519:test", 1))

    doc = document(@current, "ed25519:test", until)
    assert {:error, :invalid_key_document} = Keyring.remember("another.org", doc)

    assert {:error, :invalid_key_document} =
             Keyring.remember(@server, Map.put(doc, "valid_until_ts", until + 1))

    assert Repo.aggregate("matrix_server_keys", :count) == 0
  end

  test "one verification cannot amplify unknown signature IDs into repeated server-key fetches" do
    now = System.system_time(:millisecond)

    fetch = fn _, _ ->
      send(self(), :fetched)
      {:ok, document(@current, "ed25519:current", now + 60_000)}
    end

    Keyring.with_cache(fn ->
      assert {:error, :unknown_key} = Keyring.key(@server, "ed25519:missing1", now, fetch)
      assert {:error, :unknown_key} = Keyring.key(@server, "ed25519:missing2", now, fetch)
      assert {:ok, _} = Keyring.key(@server, "ed25519:current", now, fetch)
    end)

    assert_received :fetched
    refute_received :fetched
    assert {:error, :unknown_key} = Keyring.key(@server, "ed25519:new", now, fetch)
    assert_received :fetched
  end
end
