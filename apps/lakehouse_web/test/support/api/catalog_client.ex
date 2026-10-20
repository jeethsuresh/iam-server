defmodule LakehouseWeb.Test.Api.CatalogClient do
  import Plug.Conn
  import Phoenix.ConnTest
  @endpoint LakehouseWeb.Endpoint
  def add(token, url) do
    build_conn()
    |> put_req_header("authorization", "Bearer #{token}")
    |> put_req_header("content-type", "application/json")
    |> post("/api/v1/services", %{
      service: %{name: "Notes", home_url: "https://notes.example.com/", login_url: url}
    })
  end

  def list(token),
    do:
      build_conn()
      |> put_req_header("authorization", "Bearer #{token}")
      |> get("/api/v1/services")
end
