defmodule Interop do
  alias LakehouseMatrix.Federation.Signing
  # Test-only private TLS peers. The production transport's public-address rules remain active.
  def http(method, server, path, body \\ nil, token \\ nil)
      when server in ["native.test:8448", "reference.test:8448"] do
    headers = if token, do: [{"authorization", "Bearer " <> token}], else: []
    request(method, server, path, body, headers)
  end

  def federation(method, "reference.test:8448" = server, path, body) do
    {:ok, header} = Signing.authorization(String.upcase(to_string(method)), path, server, body)
    request(method, server, path, body, [{"authorization", header}])
  end

  def federation_media("reference.test:8448" = server, path) do
    {:ok, authorization} = Signing.authorization("GET", path, server, nil)

    case Req.get("https://" <> server <> path,
           headers: [{"authorization", authorization}],
           retry: false,
           redirect: false,
           decode_body: false,
           receive_timeout: 30_000,
           connect_options: [transport_opts: [cacertfile: "/fixtures/ca.pem"]]
         ) do
      {:ok, %{status: 200, body: body, headers: headers}} ->
        {:ok, %{body: body, headers: headers}}

      {:ok, %{status: status, body: body}} ->
        {:error, {:http, status, body}}

      error ->
        error
    end
  end

  defp request(method, server, path, body, headers) do
    options = [
      method: method,
      url: "https://" <> server <> path,
      retry: false,
      redirect: false,
      headers: headers,
      receive_timeout: 30_000,
      connect_options: [transport_opts: [cacertfile: "/fixtures/ca.pem"]]
    ]

    options = if body, do: Keyword.put(options, :json, body), else: options

    case Req.request(options) do
      {:ok, %{status: status, body: body}} when status in 200..299 -> {:ok, body}
      {:ok, %{status: status, body: body}} -> {:error, {:http, status, body}}
      error -> error
    end
  end

  def escape(value), do: URI.encode(value, &URI.char_unreserved?/1)
  def wait(fun, remaining \\ 60)

  def wait(_, 0) do
    IO.inspect(
      LakehouseIam.Repo.query!(
        "select origin, transaction_id, response from matrix_federation_transactions"
      ).rows,
      label: "transaction diagnostics"
    )

    IO.inspect(
      LakehouseIam.Repo.query!("select origin, last_error from matrix_federation_inbox").rows,
      label: "dependency diagnostics"
    )

    raise("Federation delivery timed out")
  end

  def wait(fun, remaining),
    do:
      if(fun.(),
        do: :ok,
        else:
          (
            Process.sleep(250)
            wait(fun, remaining - 1)
          )
      )

  def check(label, fun) do
    result = fun.()
    IO.puts("INTEROP PASS " <> label)
    result
  end

  def contains(server, token, room, event) do
    since = Process.get({:since, server, token})

    path =
      "/_matrix/client/v3/sync?timeout=0" <>
        if(since, do: "&since=" <> URI.encode_www_form(since), else: "")

    {:ok, sync} = http(:get, server, path, nil, token)
    Process.put({:since, server, token}, sync["next_batch"])

    Enum.any?(
      get_in(sync, ["rooms", "join", room, "timeline", "events"]) || [],
      &(&1["event_id"] == event)
    )
  end

  def send_event(server, token, room, txn, body) do
    http(
      :put,
      server,
      "/_matrix/client/v3/rooms/" <> escape(room) <> "/send/m.room.message/" <> txn,
      %{"body" => body, "msgtype" => "m.text"},
      token
    )
  end
end

repo = Application.fetch_env!(:lakehouse_iam, LakehouseIam.Repo)

Application.put_env(
  :lakehouse_iam,
  LakehouseIam.Repo,
  Keyword.merge(repo,
    database: "matrix_interop_native",
    pool: DBConnection.ConnectionPool,
    pool_size: 16
  )
)

endpoint =
  Application.fetch_env!(:lakehouse_web, LakehouseWeb.Endpoint)
  |> Keyword.merge(
    http: false,
    https: [
      ip: {0, 0, 0, 0},
      port: 8448,
      keyfile: "/fixtures/peer.key",
      certfile: "/fixtures/peer.pem"
    ],
    url: [host: "native.test", scheme: "https", port: 8448],
    server: false
  )

Application.put_env(:lakehouse_web, LakehouseWeb.Endpoint, endpoint)
Application.put_env(:lakehouse_app_demo, :enabled, false)
Application.put_env(:lakehouse_matrix, :homeserver_domain, "native.test:8448")
Application.put_env(:lakehouse_matrix, :native_event_graph, true)
Application.put_env(:lakehouse_matrix, :federation_requester, &Interop.federation/4)
Application.put_env(:lakehouse_matrix, :federation_media_requester, &Interop.federation_media/2)
Application.put_env(:lakehouse_matrix, :signing_key, Base.encode64(<<0::256>>, padding: false))
Application.put_env(:lakehouse_matrix, :signing_key_id, "ed25519:interop")

Application.put_env(:lakehouse_matrix, :federation_key_fetcher, fn server, path ->
  Interop.http(:get, server, path)
end)

Application.put_env(:lakehouse_iam, :bootstrap_on_start, false)
{:ok, _} = Application.ensure_all_started(:lakehouse_iam)
Logger.configure(level: :warning)

Ecto.Migrator.run(
  LakehouseIam.Repo,
  Application.app_dir(:lakehouse_iam, "priv/repo/migrations"),
  :up,
  all: true,
  log: false
)

{:ok, _} = Application.ensure_all_started(:lakehouse_matrix)
Application.put_env(:lakehouse_web, LakehouseWeb.Endpoint, Keyword.put(endpoint, :server, true))
{:ok, _} = Application.ensure_all_started(:lakehouse_web)
alias LakehouseMatrix.{ClientStore, Identity}
alias LakehouseMatrix.Federation.{Inbox, Outbox, RemoteJoin}
alias LakehouseMatrix.Protocol.Graph

Task.start(fn ->
  Stream.repeatedly(fn ->
    Outbox.deliver_once(&Interop.federation/4)
    Inbox.recover_once(&Interop.federation/4)
    Process.sleep(100)
  end)
  |> Stream.run()
end)

if System.get_env("INTEROP_SERVE_ONLY") != "1" do
  run_id = Integer.to_string(System.system_time(:millisecond))
  alice = LakehouseMatrix.Fixtures.user_fixture("alice" <> run_id)
  {:ok, a} = ClientStore.login(alice.username, "password123", %{"device_id" => "A"})
  at = a["access_token"]

  Interop.wait(fn ->
    match?({:ok, _}, Interop.http(:get, "reference.test:8448", "/_matrix/client/versions"))
  end)

  {:ok, b} =
    Interop.http(:post, "reference.test:8448", "/_matrix/client/v3/register", %{
      "username" => "bob" <> run_id,
      "password" => "test-password-123",
      "auth" => %{"type" => "m.login.dummy"},
      "device_id" => "B"
    })

  bt = b["access_token"]
  IO.puts("INTEROP ready")

  {:ok, room} =
    Interop.http(
      :post,
      "native.test:8448",
      "/_matrix/client/v3/createRoom",
      %{"name" => "Native-hosted", "preset" => "public_chat", "room_version" => "12"},
      at
    )

  rid = room["room_id"]

  Interop.check("Synapse joins native version 12", fn ->
    {:ok, %{"room_id" => ^rid}} =
      Interop.http(
        :post,
        "reference.test:8448",
        "/_matrix/client/v3/join/" <> Interop.escape(rid) <> "?via=native.test%3A8448",
        %{},
        bt
      )
  end)

  {:ok, message} = Interop.send_event("native.test:8448", at, rid, "native1", "native to Synapse")

  Interop.check("native message arrives in Synapse sync", fn ->
    Interop.wait(fn -> Interop.contains("reference.test:8448", bt, rid, message["event_id"]) end)
  end)

  {:ok, message} =
    Interop.send_event("reference.test:8448", bt, rid, "reference1", "Synapse to native")

  Interop.check("Synapse message arrives in native sync", fn ->
    Interop.wait(fn -> Interop.contains("native.test:8448", at, rid, message["event_id"]) end)
  end)

  {:ok, remote} =
    Interop.http(
      :post,
      "reference.test:8448",
      "/_matrix/client/v3/createRoom",
      %{"name" => "Reference-hosted", "preset" => "public_chat", "room_version" => "12"},
      bt
    )

  remote_ref = remote["room_id"]

  {:ok, old_message} =
    Interop.send_event(
      "reference.test:8448",
      bt,
      remote_ref,
      "before_join",
      "history before the native server joined"
    )

  Interop.check("native joins Synapse version 12", fn ->
    {:ok, %{"room_id" => ^remote_ref}} =
      RemoteJoin.join(alice.id, remote_ref, ["reference.test:8448"], %{}, &Interop.federation/4)
  end)

  Interop.check("native scrolls back verified pre-join Synapse history", fn ->
    {:ok, sync} =
      Interop.http(:get, "native.test:8448", "/_matrix/client/v3/sync?timeout=0", nil, at)

    token = get_in(sync, ["rooms", "join", remote_ref, "timeline", "prev_batch"])

    path =
      "/_matrix/client/v3/rooms/" <>
        Interop.escape(remote_ref) <> "/messages?dir=b&limit=100&from=" <> Interop.escape(token)

    {:ok, page} = Interop.http(:get, "native.test:8448", path, nil, at)

    unless Enum.any?(page["chunk"], &(&1["event_id"] == old_message["event_id"])),
      do: raise("Verified pre-join history was missing")
  end)

  Interop.check("native publishes in the remote room", fn ->
    {:ok, local} = Identity.parse_room_id(remote_ref)

    {:ok, _} =
      Graph.send(local, a["user_id"], "m.room.message", %{
        "body" => "joined remote",
        "msgtype" => "m.text"
      })
  end)

  Interop.check("Synapse leaves the native room", fn ->
    {:ok, %{}} =
      Interop.http(
        :post,
        "reference.test:8448",
        "/_matrix/client/v3/rooms/" <> Interop.escape(rid) <> "/leave",
        %{},
        bt
      )
  end)

  IO.puts("INTEROP COMPLETE")
end

if System.get_env("INTEROP_HOLD") == "1" do
  unless match?({:ok, _}, LakehouseIam.Accounts.fetch_user("cryptoalice")),
    do: LakehouseMatrix.Fixtures.user_fixture("cryptoalice")

  IO.puts("INTEROP CRYPTO SERVER READY")
  Process.sleep(:infinity)
end
