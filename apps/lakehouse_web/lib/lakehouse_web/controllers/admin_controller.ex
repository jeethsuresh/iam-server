defmodule LakehouseWeb.AdminController do
  use LakehouseWeb, :controller

  alias LakehouseIam.Accounts

  def index(conn, _params) do
    pending = Accounts.list_pending_users()
    render(conn, :index, pending_users: pending)
  end

  def approve(conn, params) do
    actor = conn.assigns.username
    target = Map.get(params, "username", "")

    case Accounts.approve_user(actor, target) do
      {:ok, _} ->
        conn
        |> put_flash(:info, "Approved #{Accounts.normalize_username(target)}.")
        |> redirect(to: ~p"/admin")

      {:error, :not_found} ->
        conn
        |> put_flash(:error, "User not found.")
        |> redirect(to: ~p"/admin")

      {:error, :already_active} ->
        conn
        |> put_flash(:error, "That account is already active.")
        |> redirect(to: ~p"/admin")

      {:error, :forbidden} ->
        conn
        |> put_flash(:error, "Not allowed.")
        |> redirect(to: "/")
    end
  end

  def approve_api(conn, params) do
    actor = conn.assigns.username
    target = params["username"]

    case target do
      nil ->
        conn |> put_status(:bad_request) |> json(%{message: "username is required"})

      u ->
        case Accounts.approve_user(actor, u) do
          {:ok, _} ->
            json(conn, %{message: "User approved.", username: Accounts.normalize_username(u)})

          {:error, :forbidden} ->
            conn |> put_status(:forbidden) |> json(%{message: "Forbidden"})

          {:error, :not_found} ->
            conn |> put_status(:not_found) |> json(%{message: "User not found"})

          {:error, :already_active} ->
            conn |> put_status(:conflict) |> json(%{message: "User already active"})
        end
    end
  end
end
