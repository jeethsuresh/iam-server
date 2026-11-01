defmodule LakehouseWeb.IamProfileController do
  use LakehouseWeb, :controller

  def picture(conn, %{"key" => key}) do
    with {:ok, key} <- Ecto.UUID.cast(key),
         %{picture: "data:" <> encoded} <-
           LakehouseIam.Repo.get_by(LakehouseIam.Schema.Principal, picture_key: key),
         [type, data] <- String.split(encoded, ";base64,", parts: 2),
         true <- type in ["image/png", "image/jpeg", "image/webp"],
         {:ok, bytes} <- Base.decode64(data) do
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
