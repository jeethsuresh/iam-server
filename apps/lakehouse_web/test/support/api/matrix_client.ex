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

  def create_room(token, name) do
    token
    |> with_token()
    |> post("/_matrix/client/v3/createRoom", %{"name" => name})
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

  def sync(token) do
    token
    |> with_token()
    |> get("/_matrix/client/v3/sync")
  end

  def sync_unauthenticated do
    get(build_conn(), "/_matrix/client/v3/sync")
  end
end
