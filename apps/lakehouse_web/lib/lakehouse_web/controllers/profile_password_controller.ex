defmodule LakehouseWeb.ProfilePasswordController do
  use LakehouseWeb, :controller

  alias LakehouseIam.Accounts

  def edit(conn, _params) do
    flash = Map.get(conn.assigns, :flash)
    err = flash && Phoenix.Flash.get(flash, :error)
    render(conn, :edit, error: err)
  end

  def update_browser(conn, params) do
    apply_change(conn, params, fn conn, msg ->
      jwt = LakehouseIam.Auth.Token.issue(conn.assigns.username)

      case LakehouseWeb.BrowserSession.sign_in(conn, jwt) do
        {:ok, conn} -> conn |> put_flash(:info, msg) |> redirect(to: ~p"/settings")
        {:error, conn} -> conn |> LakehouseWeb.BrowserSession.logout() |> redirect(to: ~p"/")
      end
    end)
  end

  def update_api(conn, params) do
    apply_change(conn, params, fn conn, _msg ->
      json(conn, %{message: "Password updated."})
    end)
  end

  defp apply_change(conn, params, on_ok) do
    u = conn.assigns.username
    cur = params["current_password"]
    new = params["new_password"]
    conf = params["new_password_confirm"]

    case Accounts.change_own_password(u, cur, new, conf) do
      :ok ->
        on_ok.(conn, "Password updated.")

      {:error, :forbidden, msg} ->
        respond_error(conn, :forbidden, msg)

      {:error, :unauthorized, msg} ->
        respond_error(conn, :unauthorized, msg)

      {:error, :not_found, msg} ->
        respond_error(conn, :not_found, msg)

      {:error, :bad_request, msg} ->
        respond_error(conn, :bad_request, msg)

      {:error, :internal_server_error, msg} ->
        respond_error(conn, :internal_server_error, msg)
    end
  end

  defp respond_error(conn, status, msg) do
    case get_format(conn) do
      "html" ->
        conn
        |> put_flash(:error, msg)
        |> redirect(to: ~p"/settings")

      _ ->
        st = status_to_int(status)
        body = if status == :unauthorized, do: %{message: msg}, else: %{message: msg}
        conn |> put_status(st) |> json(body)
    end
  end

  defp status_to_int(:bad_request), do: 400
  defp status_to_int(:unauthorized), do: 401
  defp status_to_int(:forbidden), do: 403
  defp status_to_int(:not_found), do: 404
  defp status_to_int(:internal_server_error), do: 500
  defp status_to_int(_), do: 400
end
