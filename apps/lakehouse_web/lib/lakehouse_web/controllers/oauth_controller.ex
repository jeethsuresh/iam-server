defmodule LakehouseWeb.OAuthController do
  use LakehouseWeb, :controller

  alias LakehouseIam.Accounts
  alias LakehouseIam.Auth.{OAuth, Token}
  alias LakehouseIam.Federated
  alias LakehouseMatrix.Memberships
  alias LakehouseWeb.IamAuth

  plug :put_layout, html: {LakehouseWeb.Layouts, :root}

  def authorize(conn, %{"sessionID" => session_id}) do
    case Federated.fetch(session_id) do
      nil ->
        conn
        |> put_flash(:error, "Unknown or expired login session.")
        |> redirect(to: ~p"/")

      sess ->
        case current_principal(conn) do
          {:ok, principal} ->
            if principal.username == sess.username do
              case IamAuth.continue_federated(principal, session_id) do
                {:ok, %{redirect: url}} ->
                  maybe_external_redirect(conn, url)

                {:error, _, body} ->
                  conn
                  |> put_flash(:error, to_string(body))
                  |> redirect(to: ~p"/")
              end
            else
              # Wrong user logged in — send to login for the expected username
              redirect(conn,
                to: ~p"/?username=#{URI.encode_www_form(sess.username)}&sessionID=#{URI.encode_www_form(session_id)}"
              )
            end

          :error ->
            redirect(conn,
              to: ~p"/?username=#{URI.encode_www_form(sess.username)}&sessionID=#{URI.encode_www_form(session_id)}"
            )
        end
    end
  end

  def authorize(conn, _params) do
    conn
    |> put_flash(:error, "sessionID required")
    |> redirect(to: ~p"/")
  end

  def consent_form(conn, %{"sessionID" => session_id}) do
    with {:ok, principal} <- current_principal(conn),
         sess when not is_nil(sess) <- Federated.fetch(session_id),
         true <- sess.username == principal.username do
      rooms = Memberships.list_joined_rooms(principal.id)

      render(conn, :consent,
        session_id: session_id,
        sess: sess,
        rooms: rooms,
        username: principal.username
      )
    else
      _ ->
        conn
        |> put_flash(:error, "Please sign in to continue.")
        |> redirect(to: ~p"/?sessionID=#{URI.encode_www_form(session_id || "")}")
    end
  end

  def consent_submit(conn, params) do
    session_id = params["sessionID"]

    with {:ok, principal} <- current_principal(conn),
         sess when not is_nil(sess) <- Federated.fetch(session_id),
         true <- sess.username == principal.username do
      room_mode = if params["all_rooms"] in ["true", "on", "1"], do: :all, else: :selected

      room_ids =
        case params["room_ids"] do
          list when is_list(list) -> list
          id when is_binary(id) and id != "" -> [id]
          _ -> []
        end

      case OAuth.issue_code_redirect(sess, principal.id, room_mode, room_ids) do
        {:ok, url} ->
          _ = Federated.delete(session_id)
          redirect(conn, external: url)

        {:error, _} ->
          conn
          |> put_flash(:error, "Could not complete consent.")
          |> redirect(to: ~p"/oauth/consent?sessionID=#{URI.encode_www_form(session_id)}")
      end
    else
      _ ->
        conn
        |> put_flash(:error, "Session expired.")
        |> redirect(to: ~p"/")
    end
  end

  def token(conn, params) do
    grant_type = params["grant_type"]

    case grant_type do
      "authorization_code" ->
        code = params["code"]
        verifier = params["code_verifier"]
        redirect_uri = params["redirect_uri"]

        case OAuth.exchange_code(code, verifier, redirect_uri) do
          {:ok, tokens} ->
            json(conn, tokens)

          {:error, :redirect_mismatch} ->
            conn |> put_status(400) |> json(%{error: "invalid_grant", error_description: "redirect_uri mismatch"})

          {:error, :invalid_code_verifier} ->
            conn |> put_status(400) |> json(%{error: "invalid_grant", error_description: "PKCE verification failed"})

          {:error, _} ->
            conn |> put_status(400) |> json(%{error: "invalid_grant"})
        end

      "refresh_token" ->
        case LakehouseIam.Apps.Tokens.refresh(params["refresh_token"]) do
          {:ok, tokens} ->
            json(conn, tokens)

          {:error, _} ->
            conn |> put_status(400) |> json(%{error: "invalid_grant"})
        end

      _ ->
        conn |> put_status(400) |> json(%{error: "unsupported_grant_type"})
    end
  end

  defp current_principal(conn) do
    case get_session(conn, :user_jwt) do
      token when is_binary(token) and token != "" ->
        case Token.verify(token) do
          {:ok, %{"username" => username}} -> Accounts.fetch_user(username)
          _ -> :error
        end

      _ ->
        :error
    end
  end

  defp maybe_external_redirect(conn, "/" <> _ = path), do: redirect(conn, to: path)
  defp maybe_external_redirect(conn, url), do: redirect(conn, external: url)
end
