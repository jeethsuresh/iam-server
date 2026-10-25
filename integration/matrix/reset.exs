# Rehearse the maintenance entry point with no Matrix application or workers.
# The database is newly created here and is the only database this script drops.
{:ok, _} = Application.ensure_all_started(:ecto_sql)
{:ok, _} = Application.ensure_all_started(:postgrex)
Logger.configure(level: :warning)
repo = Application.fetch_env!(:lakehouse_iam, LakehouseIam.Repo)
database = "matrix_reset_rehearsal_" <> Integer.to_string(System.system_time(:microsecond))
opts = Keyword.merge(repo, database: database, pool: DBConnection.ConnectionPool, pool_size: 4)
Application.put_env(:lakehouse_iam, LakehouseIam.Repo, opts)
Application.put_env(:lakehouse_iam, :bootstrap_on_start, false)
Application.put_env(:lakehouse_matrix, :homeserver_domain, "reset.test")
Application.put_env(:lakehouse_matrix, :native_event_graph, true)
Application.put_env(:lakehouse_matrix, :signing_key, Base.encode64(<<0::256>>, padding: false))
Application.put_env(:lakehouse_matrix, :signing_key_id, "ed25519:reset_test")
root = Path.join(System.tmp_dir!(), database)
Application.put_env(:lakehouse_matrix, :media_root, root)
Application.put_env(:lakehouse_matrix, :media_store, LakehouseMatrix.Media.Store.Local)
:ok = LakehouseIam.Repo.__adapter__().storage_up(opts)

try do
  LakehouseIam.Release.migrate()
  {:ok, _} = Application.ensure_all_started(:lakehouse_iam)
  principal = LakehouseMatrix.Fixtures.user_fixture("rehearsal")
  {:ok, %{"room_id" => old_room}} = LakehouseMatrix.ClientRooms.create(principal.id, %{})

  {:ok, session} =
    LakehouseMatrix.ClientStore.login("rehearsal", "password123", %{"device_id" => "D"})

  {:ok, _} =
    LakehouseMatrix.ClientStore.put_data(principal.id, "", "m.secret_storage.default_key", %{
      "key" => "keep-global"
    })

  {:ok, backup} =
    LakehouseMatrix.KeyBackups.create(principal.id, %{
      "algorithm" => "m.megolm_backup.v1.curve25519-aes-sha2",
      "auth_data" => %{"public_key" => Base.encode64(<<1::256>>, padding: false)}
    })

  {:ok, upload} = LakehouseMatrix.Media.upload(principal.id, "preserve upload")

  token =
    LakehouseMatrix.Cursor.encode(
      "sync",
      principal.id,
      "D",
      LakehouseMatrix.ClientStore.position()
    )

  :ok = Application.stop(:lakehouse_iam)
  %{"rooms" => 1} = LakehouseMatrix.Release.room_reset_plan()
  %{"rooms_after" => 0} = LakehouseMatrix.Release.reset_rooms("reset.test")

  {:ok, :ok, _} =
    Ecto.Migrator.with_repo(LakehouseIam.Repo, fn repo ->
      true = repo.get!(LakehouseIam.Schema.Principal, principal.id).active
      true = LakehouseIam.Accounts.password_valid?("rehearsal", "password123")
      :error = LakehouseMatrix.ClientStore.authenticate(session["access_token"])
      {:error, :invalid_cursor} = LakehouseMatrix.Cursor.decode(token, "sync", principal.id, "D")

      %{"key" => "keep-global"} =
        LakehouseMatrix.ClientStore.get_data(principal.id, "", "m.secret_storage.default_key")

      {:ok, %{"version" => version}} = LakehouseMatrix.KeyBackups.version(principal.id)
      true = version == backup["version"]

      {:ok, %{body: "preserve upload"}} =
        LakehouseMatrix.Media.download(principal.id, "reset.test", upload.media_id)

      {:ok, %{"room_id" => fresh}} = LakehouseMatrix.ClientRooms.create(principal.id, %{})
      true = fresh != old_room
      :ok
    end)

  IO.puts(
    "RESET PASS explicit release entry point clears rooms and cursors while preserving identity, uploads, encrypted backups and global secrets"
  )
after
  Application.stop(:lakehouse_iam)
  if pid = Process.whereis(LakehouseIam.Repo), do: Supervisor.stop(pid)
  :ok = LakehouseIam.Repo.__adapter__().storage_down(opts)
  File.rm_rf!(root)
end
