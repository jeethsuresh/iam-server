defmodule LakehouseMatrix.Protocol.KeyBackupsTest do
  use LakehouseMatrix.DataCase, async: false
  alias LakehouseMatrix.{Fixtures, KeyBackups}
  @room "!remote:example.org"
  @metadata %{
    "algorithm" => "m.megolm_backup.v1.curve25519-aes-sha2",
    "auth_data" => %{"public_key" => "client-public-key", "signatures" => %{}}
  }
  setup do
    alice = Fixtures.user_fixture("backupalice")
    bob = Fixtures.user_fixture("backupbob")
    {:ok, %{"version" => version}} = KeyBackups.create(alice.id, @metadata)
    %{alice: alice, bob: bob, version: version}
  end

  defp data(index, verified \\ false),
    do: %{
      "first_message_index" => index,
      "forwarded_count" => 0,
      "is_verified" => verified,
      "session_data" => %{
        "ciphertext" => "encrypted-on-client",
        "mac" => "mac",
        "ephemeral" => "public-ephemeral"
      }
    }

  test "encrypted backup data is account-private and round-trips at all three granularities",
       ctx do
    payload = %{"rooms" => %{@room => %{"sessions" => %{"session" => data(10)}}}}

    assert {:ok, %{"count" => 1, "etag" => "1"}} =
             KeyBackups.put(ctx.alice.id, ctx.version, payload)

    assert {:ok, ^payload} = KeyBackups.get(ctx.alice.id, ctx.version)
    assert {:ok, %{"sessions" => sessions}} = KeyBackups.get(ctx.alice.id, ctx.version, @room)
    assert sessions["session"] == data(10)
    assert {:ok, stored} = KeyBackups.get(ctx.alice.id, ctx.version, @room, "session")
    assert stored == data(10)
    assert {:error, :not_found} = KeyBackups.get(ctx.bob.id, ctx.version)
    assert {:error, :not_found} = KeyBackups.version(ctx.bob.id, ctx.version)
    assert {:ok, %{}} = KeyBackups.delete_version(ctx.bob.id, ctx.version)
    assert {:ok, %{"count" => 1}} = KeyBackups.version(ctx.alice.id, ctx.version)
  end

  test "verified sessions and earlier message indices win and duplicate uploads preserve the etag",
       ctx do
    assert {:ok, %{"etag" => "1"}} =
             KeyBackups.put(ctx.alice.id, ctx.version, data(10), @room, "session")

    assert {:ok, %{"etag" => "1"}} =
             KeyBackups.put(ctx.alice.id, ctx.version, data(20), @room, "session")

    assert {:ok, %{"etag" => "2"}} =
             KeyBackups.put(ctx.alice.id, ctx.version, data(30, true), @room, "session")

    assert {:ok, %{"etag" => "2"}} =
             KeyBackups.put(ctx.alice.id, ctx.version, data(0), @room, "session")

    assert {:ok, %{"etag" => "3"}} =
             KeyBackups.put(ctx.alice.id, ctx.version, data(5, true), @room, "session")

    assert {:ok, value} = KeyBackups.get(ctx.alice.id, ctx.version, @room, "session")
    assert value == data(5, true)
  end

  test "uploads target only the latest backup while previous versions remain readable and deletion is idempotent",
       ctx do
    {:ok, %{"version" => newer}} = KeyBackups.create(ctx.alice.id, @metadata)

    assert {:error, {:wrong_backup_version, ^newer}} =
             KeyBackups.put(ctx.alice.id, ctx.version, data(0), @room, "s")

    assert {:ok, %{"rooms" => %{}}} = KeyBackups.get(ctx.alice.id, ctx.version)
    assert {:ok, _} = KeyBackups.put(ctx.alice.id, newer, data(0), @room, "s")
    assert {:ok, %{"count" => 0, "etag" => "2"}} = KeyBackups.delete(ctx.alice.id, newer, @room)
    assert {:ok, %{}} = KeyBackups.delete_version(ctx.alice.id, newer)
    assert {:ok, %{}} = KeyBackups.delete_version(ctx.alice.id, newer)
    assert {:error, :not_found} = KeyBackups.get(ctx.alice.id, newer)
  end
end
