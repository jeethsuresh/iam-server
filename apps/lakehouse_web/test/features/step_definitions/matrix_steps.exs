defmodule LakehouseWeb.Bdd.MatrixSteps do
  use Cucumber.StepDefinition
  import ExUnit.Assertions
  import Phoenix.ConnTest

  alias LakehouseIam.{Accounts, Repo}
  alias LakehouseIam.Schema.Grant
  alias LakehouseWeb.MatrixFixtures
  alias LakehouseWeb.Test.Api.MatrixClient

  import Ecto.Query

  step "I matrix-login as {string}", %{args: [username]} = context do
    password = get_in(context, [:users, username]) || "password123"
    ensure_user(username, password)
    conn = MatrixClient.login(username, password)
    assert %{"access_token" => token} = json_response(conn, 200)

    tokens = Map.get(context, :matrix_tokens, %{})
    {:ok, Map.merge(context, %{matrix_token: token, matrix_tokens: Map.put(tokens, username, token)})}
  end

  step "I create a matrix room named {string}", %{args: [name]} = context do
    token = Map.fetch!(context, :matrix_token)
    conn = MatrixClient.create_room(token, name)
    assert %{"room_id" => room_id} = json_response(conn, 200)

    {:ok, Map.merge(context, %{last_conn: conn, room_id: room_id, room_name: name})}
  end

  step "I create a public matrix room named {string}", %{args: [name]} = context do
    token = Map.fetch!(context, :matrix_token)
    conn = MatrixClient.create_room(token, name, %{"preset" => "public_chat"})
    assert %{"room_id" => room_id} = json_response(conn, 200)
    {:ok, Map.merge(context, %{last_conn: conn, room_id: room_id, room_name: name})}
  end

  step "I invite {string} to the room via API", %{args: [user_id]} = context do
    token = Map.fetch!(context, :matrix_token)
    room_id = Map.fetch!(context, :room_id)
    conn = MatrixClient.invite(token, room_id, user_id)
    assert conn.status == 200
    {:ok, Map.put(context, :last_conn, conn)}
  end

  step "{string} sync invite section should include the room", %{args: [username]} = context do
    token = matrix_token!(context, username)
    room_id = Map.fetch!(context, :room_id)
    conn = MatrixClient.sync(token)
    assert %{"rooms" => %{"invite" => invite}} = json_response(conn, 200)
    assert Map.has_key?(invite, room_id)
    :ok
  end

  step "{string} sync invite section should not include the room", %{args: [username]} = context do
    token = matrix_token!(context, username)
    room_id = Map.fetch!(context, :room_id)
    conn = MatrixClient.sync(token)
    assert %{"rooms" => %{"invite" => invite}} = json_response(conn, 200)
    refute Map.has_key?(invite, room_id)
    :ok
  end

  step "{string} joins the room via API", %{args: [username]} = context do
    password = get_in(context, [:users, username]) || "password123"
    ensure_user(username, password)
    room_id = Map.fetch!(context, :room_id)

    login = MatrixClient.login(username, password)
    assert %{"access_token" => token} = json_response(login, 200)
    conn = MatrixClient.join(token, room_id)
    assert conn.status == 200

    tokens = Map.get(context, :matrix_tokens, %{})
    {:ok, Map.put(context, :matrix_tokens, Map.put(tokens, username, token))}
  end

  step "{string} sends matrix message {string} with txn {string}",
       %{args: [username, body, txn]} = context do
    token = matrix_token!(context, username)
    room_id = Map.fetch!(context, :room_id)
    conn = MatrixClient.send_message(token, room_id, body, txn)
    {:ok, Map.put(context, :last_conn, conn)}
  end

  step "I send matrix message {string}", %{args: [body]} = context do
    token = Map.fetch!(context, :matrix_token)
    room_id = Map.fetch!(context, :room_id)
    txn = "txn-#{System.unique_integer([:positive])}"
    conn = MatrixClient.send_message(token, room_id, body, txn)
    {:ok, Map.merge(context, %{last_conn: conn, last_message: body})}
  end

  step "room messages should include {string}", %{args: [body]} = context do
    token = Map.fetch!(context, :matrix_token)
    room_id = Map.fetch!(context, :room_id)
    conn = MatrixClient.messages(token, room_id)
    assert %{"chunk" => chunk} = json_response(conn, 200)
    assert Enum.any?(chunk, &(&1["content"]["body"] == body))
    :ok
  end

  step "{string} room messages should include {string}", %{args: [username, body]} = context do
    token = matrix_token!(context, username)
    room_id = Map.fetch!(context, :room_id)
    conn = MatrixClient.messages(token, room_id)
    assert %{"chunk" => chunk} = json_response(conn, 200)
    assert Enum.any?(chunk, &(&1["content"]["body"] == body)),
           "#{username} messages missing #{inspect(body)} in #{inspect(Enum.map(chunk, & &1["content"]["body"]))}"

    :ok
  end

  step "{string} sync timeline should include {string}", %{args: [username, body]} = context do
    token = matrix_token!(context, username)
    room_id = Map.fetch!(context, :room_id)
    conn = MatrixClient.sync(token)
    assert %{"rooms" => %{"join" => join}} = json_response(conn, 200)
    assert Map.has_key?(join, room_id)
    events = get_in(join, [room_id, "timeline", "events"]) || []

    assert Enum.any?(events, &(&1["content"]["body"] == body)),
           "#{username} sync missing #{inspect(body)}"

    :ok
  end

  step "{string} sync should include the room", %{args: [username]} = context do
    token = matrix_token!(context, username)
    room_id = Map.fetch!(context, :room_id)
    conn = MatrixClient.sync(token)
    assert %{"rooms" => %{"join" => join}} = json_response(conn, 200)
    assert Map.has_key?(join, room_id)
    :ok
  end

  step "{string} leaves the room via API", %{args: [username]} = context do
    token = matrix_token!(context, username)
    room_id = Map.fetch!(context, :room_id)
    conn = MatrixClient.leave(token, room_id)
    assert conn.status == 200
    {:ok, Map.put(context, :last_conn, conn)}
  end

  step "{string} sync should not include the room", %{args: [username]} = context do
    token = matrix_token!(context, username)
    room_id = Map.fetch!(context, :room_id)
    conn = MatrixClient.sync(token)
    assert %{"rooms" => %{"join" => join}} = json_response(conn, 200)
    refute Map.has_key?(join, room_id)
    :ok
  end

  step "unauthenticated matrix sync", context do
    conn = MatrixClient.sync_unauthenticated()
    {:ok, Map.put(context, :last_conn, conn)}
  end

  step "user {string} has no send permission", %{args: [username]} = context do
    ensure_user(username, "password123")
    {:ok, principal} = Accounts.fetch_user(Accounts.normalize_username(username))

    Repo.delete_all(from g in Grant, where: g.principal_id == ^principal.id)
    {:ok, Map.put(context, :no_send_user, username)}
  end

  step "{string} attempts to send matrix message {string}", %{args: [username, body]} = context do
    password = "password123"
    login = MatrixClient.login(username, password)
    assert %{"access_token" => token} = json_response(login, 200)
    room_id = Map.fetch!(context, :room_id)
    _ = MatrixClient.join(token, room_id)
    conn = MatrixClient.send_message(token, room_id, body, "denied1")
    {:ok, Map.put(context, :last_conn, conn)}
  end

  step "two users send distinct messages in the same room", context do
    room_id = Map.fetch!(context, :room_id)
    alice = matrix_token!(context, "alice")
    bob = matrix_token!(context, "bob")

    assert MatrixClient.send_message(alice, room_id, "concurrent-alice", "ca1").status == 200
    assert MatrixClient.send_message(bob, room_id, "concurrent-bob", "cb1").status == 200

    messages = MatrixClient.messages(alice, room_id) |> json_response(200)
    bodies = Enum.map(messages["chunk"], & &1["content"]["body"])
    assert "concurrent-alice" in bodies
    assert "concurrent-bob" in bodies
    :ok
  end

  step "I upload media file {string} as image via API", %{args: [filename]} = context do
    token = Map.fetch!(context, :matrix_token)
    body = sample_png()
    conn = MatrixClient.upload_media(token, body, filename, "image/png")
    assert %{"content_uri" => uri, "info" => info} = json_response(conn, 200)

    {:ok,
     Map.merge(context, %{
       last_conn: conn,
       last_media_uri: uri,
       last_media_info: info,
       last_media_body: body,
       last_upload_name: filename
     })}
  end

  step "I send the uploaded media as an image message", context do
    token = Map.fetch!(context, :matrix_token)
    room_id = Map.fetch!(context, :room_id)
    uri = Map.fetch!(context, :last_media_uri)
    info = Map.get(context, :last_media_info, %{})
    name = Map.fetch!(context, :last_upload_name)

    content = %{
      "msgtype" => "m.image",
      "body" => name,
      "url" => uri,
      "info" => info
    }

    conn =
      MatrixClient.send_file_message(
        token,
        room_id,
        content,
        "img-#{System.unique_integer([:positive])}"
      )

    assert conn.status == 200
    {:ok, Map.put(context, :last_conn, conn)}
  end

  step "I can download the uploaded media via API", context do
    token = Map.fetch!(context, :matrix_token)
    uri = Map.fetch!(context, :last_media_uri)
    assert "mxc://" <> rest = uri
    [server, media_id] = String.split(rest, "/", parts: 2)
    conn = MatrixClient.download_media(token, server, media_id)
    assert conn.status == 200
    assert byte_size(conn.resp_body) > 0
    :ok
  end

  step "I set the room name via API to {string}", %{args: [name]} = context do
    token = Map.fetch!(context, :matrix_token)
    room_id = Map.fetch!(context, :room_id)
    conn = MatrixClient.set_room_name(token, room_id, name)
    {:ok, Map.put(context, :last_conn, conn)}
  end

  step "I set the room avatar to the uploaded media via API", context do
    token = Map.fetch!(context, :matrix_token)
    room_id = Map.fetch!(context, :room_id)
    uri = Map.fetch!(context, :last_media_uri)
    info = Map.get(context, :last_media_info, %{})
    conn = MatrixClient.set_room_avatar(token, room_id, uri, info)
    {:ok, Map.put(context, :last_conn, conn)}
  end

  step "I kick {string} from the room via API", %{args: [username]} = context do
    token = Map.fetch!(context, :matrix_token)
    room_id = Map.fetch!(context, :room_id)
    conn = MatrixClient.kick(token, room_id, "@#{username}:localhost")
    {:ok, Map.put(context, :last_conn, conn)}
  end

  step "{string} attempts to kick {string} from the room via API",
       %{args: [actor, target]} = context do
    token = matrix_token!(context, actor)
    room_id = Map.fetch!(context, :room_id)
    conn = MatrixClient.kick(token, room_id, "@#{target}:localhost")
    {:ok, Map.put(context, :last_conn, conn)}
  end

  defp sample_png do
    path = Path.join(System.tmp_dir!(), "bdd-png-#{System.unique_integer([:positive])}.png")
    {_, 0} = System.cmd("magick", ["-size", "120x80", "plasma:fractal", path], stderr_to_stdout: true)
    data = File.read!(path)
    File.rm(path)
    data
  end

  defp ensure_user(username, password) do
    MatrixFixtures.ensure_rbac!()

    case Accounts.fetch_user(Accounts.normalize_username(username)) do
      {:ok, _} ->
        :ok

      :error ->
        _ = MatrixFixtures.user_fixture(username)

        if password != "password123" do
          :ok = Accounts.change_own_password(username, "password123", password, password)
        end

        :ok
    end
  end

  defp matrix_token!(context, username) do
    Map.fetch!(context.matrix_tokens, username)
  end
end
