defmodule LakehouseWeb.Test.Api.IamClient do
  @moduledoc false
  import Plug.Conn
  import Phoenix.ConnTest

  @endpoint LakehouseWeb.Endpoint

  def register(username, password) do
    build_conn()
    |> put_req_header("content-type", "application/json")
    |> post("/register", %{"username" => username, "password" => password})
  end

  def login(username, password) do
    build_conn()
    |> put_req_header("content-type", "application/json")
    |> post("/login", %{"username" => username, "password" => password})
  end

  def approve(admin_token, username) do
    build_conn()
    |> put_req_header("authorization", "Bearer #{admin_token}")
    |> put_req_header("content-type", "application/json")
    |> post("/admin/approve", %{"username" => username})
  end

  def change_password(token, current, new_password, confirm \\ nil) do
    confirm = confirm || new_password

    build_conn()
    |> put_req_header("authorization", "Bearer #{token}")
    |> put_req_header("content-type", "application/json")
    |> post("/profile/password", %{
      "current_password" => current,
      "new_password" => new_password,
      "new_password_confirm" => confirm
    })
  end
end
