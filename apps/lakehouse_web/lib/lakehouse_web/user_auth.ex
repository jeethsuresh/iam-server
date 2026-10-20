defmodule LakehouseWeb.UserAuth do
  @moduledoc """
  LiveView `on_mount` hooks for session-backed browser auth.
  """
  use Phoenix.VerifiedRoutes,
    endpoint: LakehouseWeb.Endpoint,
    router: LakehouseWeb.Router,
    statics: LakehouseWeb.StaticPaths.paths()

  import Phoenix.Component
  import Phoenix.LiveView

  def on_mount(:require_user, _params, session, socket) do
    case session["user_jwt"] do
      token when is_binary(token) and token != "" ->
        case LakehouseIam.Auth.Token.verify(token) do
          {:ok, claims} ->
            username = claims["username"]

            case LakehouseIam.Accounts.fetch_user(username) do
              {:ok, %{active: true} = principal} ->
                {:cont,
                 assign(socket,
                   username: username,
                   principal_id: principal.id,
                   current_user_is_admin: LakehouseIam.Accounts.admin?(username)
                 )}

              _ ->
                {:halt, redirect(socket, to: ~p"/")}
            end

          :error ->
            {:halt, redirect(socket, to: ~p"/")}
        end

      _ ->
        {:halt, redirect(socket, to: ~p"/")}
    end
  end
end
