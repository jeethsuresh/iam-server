defmodule LakehouseWeb.Plugs.RequireAdmin do
  @moduledoc false
  import Plug.Conn
  import Phoenix.Controller, only: [put_flash: 3, redirect: 2, get_format: 1]

  def init(opts), do: opts

  def call(conn, _opts) do
    if LakehouseIam.Accounts.admin?(conn.assigns.username) do
      conn
    else
      deny(conn)
    end
  end

  defp deny(conn) do
    if html_request?(conn) do
      conn
      |> put_flash(:error, "That page is only available to administrators.")
      |> redirect(to: "/")
      |> halt()
    else
      conn
      |> put_resp_content_type("application/json")
      |> send_resp(403, Jason.encode!(%{message: "Forbidden"}))
      |> halt()
    end
  end

  defp html_request?(conn) do
    case get_format(conn) do
      "html" -> true
      _ -> false
    end
  end
end
