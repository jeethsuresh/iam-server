defmodule LakehouseWeb.IamProfileController do
  use LakehouseWeb, :controller

  def picture(conn, %{"key" => key}) do
    with {:ok, key} <- Ecto.UUID.cast(key),
         %{content_type: type, data: bytes} <-
           LakehouseIam.Repo.get(LakehouseIam.Schema.ProfilePicture, key),
         true <- type in ["image/png", "image/jpeg", "image/webp"] do
      conn
      |> put_resp_header("cache-control", "no-store")
      |> put_resp_header("x-content-type-options", "nosniff")
      |> put_resp_content_type(type)
      |> send_resp(200, bytes)
    else
      _ -> send_resp(conn, 404, "Not found")
    end
  end

  def show(conn, _params) do
    case get_format(conn) do
      "html" ->
        redirect(conn, to: ~p"/settings")

      _ ->
        json(conn, %{username: conn.assigns.username})
    end
  end
end
