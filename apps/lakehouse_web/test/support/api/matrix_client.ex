defmodule LakehouseWeb.Test.Api.MatrixClient do
  @moduledoc false
  import Plug.Conn
  import Phoenix.ConnTest

  @endpoint LakehouseWeb.Endpoint

  def login(username, password \\ "password123") do
    build_conn()
    |> put_req_header("content-type", "application/json")
    |> post("/_matrix/client/v3/login", %{
      "type" => "m.login.password",
      "identifier" => %{"type" => "m.id.user", "user" => username},
      "password" => password
    })
  end

  def with_token(token) do
    build_conn()
    |> put_req_header("authorization", "Bearer #{token}")
    |> put_req_header("content-type", "application/json")
  end

  def create_room(token, name, params \\ %{}) do
    token
    |> with_token()
    |> post("/_matrix/client/v3/createRoom", Map.put(params, "name", name))
  end

  def join(token, room_id) do
    token
    |> with_token()
    |> post("/_matrix/client/v3/join/#{room_id}", %{})
  end

  def leave(token, room_id) do
    token
    |> with_token()
    |> post("/_matrix/client/v3/rooms/#{room_id}/leave", %{})
  end

  def invite(token, room_id, user_id) do
    token
    |> with_token()
    |> post("/_matrix/client/v3/rooms/#{room_id}/invite", %{"user_id" => user_id})
  end

  def sync(token, opts \\ []) do
    qs =
      []
      |> then(fn q -> if opts[:since], do: [{"since", opts[:since]} | q], else: q end)
      |> then(fn q -> if opts[:timeout], do: [{"timeout", to_string(opts[:timeout])} | q], else: q end)
      |> URI.encode_query()

    path = if qs == "", do: "/_matrix/client/v3/sync", else: "/_matrix/client/v3/sync?#{qs}"

    token
    |> with_token()
    |> get(path)
  end

  def send_message(token, room_id, body, txn_id \\ "t1") do
    token
    |> with_token()
    |> put("/_matrix/client/v3/rooms/#{room_id}/send/m.room.message/#{txn_id}", %{
      "msgtype" => "m.text",
      "body" => body
    })
  end

  def messages(token, room_id) do
    token
    |> with_token()
    |> get("/_matrix/client/v3/rooms/#{room_id}/messages")
  end

  def upload_media(token, body, filename, content_type \\ "application/octet-stream") do
    token
    |> with_token()
    |> put_req_header("content-type", "application/json")
    |> post("/_matrix/media/v3/upload?filename=#{URI.encode(filename)}", %{
      "base64" => Base.encode64(body),
      "content_type" => content_type,
      "filename" => filename
    })
  end

  def download_media(token, server_name, media_id) do
    token
    |> with_token()
    |> get("/_matrix/media/v3/download/#{server_name}/#{media_id}")
  end

  def set_room_name(token, room_id, name) do
    token
    |> with_token()
    |> put("/_matrix/client/v3/rooms/#{room_id}/state/m.room.name", %{"name" => name})
  end

  def set_room_avatar(token, room_id, content_uri, info \\ %{}) do
    token
    |> with_token()
    |> put("/_matrix/client/v3/rooms/#{room_id}/state/m.room.avatar", %{
      "url" => content_uri,
      "info" => info
    })
  end

  def kick(token, room_id, user_id) do
    token
    |> with_token()
    |> post("/_matrix/client/v3/rooms/#{room_id}/kick", %{"user_id" => user_id})
  end

  def send_file_message(token, room_id, content, txn_id \\ "file1") do
    token
    |> with_token()
    |> put("/_matrix/client/v3/rooms/#{room_id}/send/m.room.message/#{txn_id}", content)
  end

  def sync_unauthenticated do
    get(build_conn(), "/_matrix/client/v3/sync")
  end
end
