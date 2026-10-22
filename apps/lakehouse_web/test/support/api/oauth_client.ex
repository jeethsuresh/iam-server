defmodule LakehouseWeb.Test.Api.OAuthClient do
  @moduledoc false
  import Plug.Conn
  import Phoenix.ConnTest

  @endpoint LakehouseWeb.Endpoint

  def browser_login(username, password),
    do: post(build_conn(), "/web/login", %{username: username, password: password})

  def browser_logout(conn), do: conn |> recycle() |> post("/web/logout")
  def browser_start(conn, params), do: conn |> recycle() |> get("/oauth/start", params)

  def session_check(raw),
    do: build_conn() |> put_req_header("authorization", "Bearer " <> raw) |> get("/oauth/session")

  def backend_register(attrs) do
    build_conn()
    |> put_req_header("content-type", "application/json")
    |> post("/backend/register", attrs)
  end

  def token(params) do
    build_conn()
    |> put_req_header("content-type", "application/x-www-form-urlencoded")
    |> post("/oauth/token", params)
  end

  def me(access_token) do
    build_conn()
    |> put_req_header("authorization", "Bearer #{access_token}")
    |> get("/app/v1/me")
  end

  def chats(access_token) do
    build_conn()
    |> put_req_header("authorization", "Bearer #{access_token}")
    |> get("/app/v1/chats")
  end

  def list_events(access_token, room_id) do
    build_conn()
    |> put_req_header("authorization", "Bearer #{access_token}")
    |> get("/app/v1/chats/#{room_id}/events")
  end

  def create_event(access_token, room_id, body) do
    build_conn()
    |> put_req_header("authorization", "Bearer #{access_token}")
    |> put_req_header("content-type", "application/json")
    |> post("/app/v1/chats/#{room_id}/events", %{"body" => body})
  end
end
