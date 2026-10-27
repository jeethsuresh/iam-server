defmodule LakehouseWeb.OAuthController do
  use LakehouseWeb, :controller

  alias LakehouseIam.Accounts
  alias LakehouseIam.Auth.{OAuth, Token}
  alias LakehouseIam.Federated
  alias LakehouseMatrix.Memberships
  alias LakehouseWeb.IamAuth

  plug :put_layout, html: {LakehouseWeb.Layouts, :root}

  def start(conn, params) do
    state = params["state"]

    valid =
      is_binary(state) and byte_size(state) in 1..1024 and
        params["prompt"] in [nil, "", "none"] and params["screen"] in [nil, "", "register"] and
        not (params["prompt"] == "none" and params["screen"] == "register")

    attrs = Map.put(params, "username", params["login_hint"] || params["username"])

    if valid do
      case Federated.register(attrs) do
        {:ok, session_id, _username} ->
          if params["screen"] == "register",
            do: redirect(conn, to: IamAuth.registration_path(session_id)),
            else: authorize(conn, Map.put(params, "sessionID", session_id))

        {:error, message} ->
          conn |> put_status(400) |> text(message)
      end
    else
      conn |> put_status(400) |> text("A valid state, prompt and screen are required.")
    end
  end

  def authorize(conn, %{"sessionID" => session_id} = params) do
    silent = params["prompt"] == "none"

    case Federated.fetch(session_id) do
      nil ->
        if silent do
          conn |> put_status(400) |> text("Unknown or expired login session.")
        else
          conn |> put_flash(:error, "Unknown or expired login session.") |> redirect(to: ~p"/")
        end

      sess ->
        cond do
          params["prompt"] not in [nil, "", "none"] ->
            conn |> put_status(400) |> text("Unsupported prompt.")

          silent and (not is_binary(sess.state) or sess.state == "") ->
            conn |> put_status(400) |> text("Silent login requires app-owned state.")

          true ->
            authorize_session(conn, session_id, sess, silent)
        end
    end
  end

  def authorize(conn, _params) do
    conn |> put_flash(:error, "sessionID required") |> redirect(to: ~p"/")
  end

  defp authorize_session(conn, session_id, sess, silent) do
    case current_principal(conn) do
      {:ok, principal} ->
        case IamAuth.continue_federated(principal, session_id,
               silent: silent,
               session_id: family_id(conn)
             ) do
          {:ok, %{redirect: url}} ->
            maybe_external_redirect(conn, url)

          {:error, :consent_required, _} ->
            silent_error(conn, session_id, sess, "consent_required")

          {:error, _, _} ->
            if silent,
              do: silent_error(conn, session_id, sess, "login_required"),
              else: redirect(conn, to: IamAuth.login_path(sess.username, session_id))
        end

      :error ->
        if silent,
          do: silent_error(conn, session_id, sess, "login_required"),
          else: redirect(conn, to: IamAuth.login_path(sess.username, session_id))
    end
  end

  defp silent_error(conn, session_id, sess, error) do
    url = OAuth.error_redirect(sess, error)
    :ok = Federated.delete(session_id)
    redirect(conn, external: url)
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
      room_mode =
        if "matrix.full" in sess.scopes or params["all_rooms"] in ["true", "on", "1"],
          do: :all,
          else: :selected

      room_ids =
        case params["room_ids"] do
          list when is_list(list) -> list
          id when is_binary(id) and id != "" -> [id]
          _ -> []
        end

      case OAuth.issue_code_redirect(sess, principal.id, room_mode, room_ids,
             session_id: family_id(conn)
           ) do
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

  def session_check(conn, _params) do
    result =
      case get_req_header(conn, "authorization") do
        ["Bearer " <> raw] -> LakehouseIam.Apps.Tokens.check_session(raw)
        _ -> {:error, :invalid}
      end

    conn = put_resp_header(conn, "cache-control", "no-store")

    case result do
      {:ok, status} -> json(conn, status)
      _ -> conn |> put_status(401) |> json(%{active: false, error: "invalid_token"})
    end
  rescue
    _error in [DBConnection.ConnectionError, Postgrex.Error] ->
      conn
      |> put_resp_header("cache-control", "no-store")
      |> put_status(503)
      |> json(%{error: "temporarily_unavailable"})
  end

  defp family_id(conn) do
    case Token.verify(get_session(conn, :user_jwt)) do
      {:ok, %{"sid" => id}} -> id
      _ -> nil
    end
  end

  def token(conn, params) do
    conn = put_resp_header(conn, "cache-control", "no-store")
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
            conn
            |> put_status(400)
            |> json(%{error: "invalid_grant", error_description: "redirect_uri mismatch"})

          {:error, :invalid_code_verifier} ->
            conn
            |> put_status(400)
            |> json(%{error: "invalid_grant", error_description: "PKCE verification failed"})

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
  rescue
    _error in [DBConnection.ConnectionError, Postgrex.Error] ->
      conn
      |> put_resp_header("cache-control", "no-store")
      |> put_status(503)
      |> json(%{error: "temporarily_unavailable"})
  end

  defp current_principal(conn) do
    case get_session(conn, :user_jwt) do
      token when is_binary(token) and token != "" ->
        case Token.verify(token) do
          {:ok, %{"username" => username, "sid" => sid}} when is_binary(sid) ->
            case Accounts.fetch_user(username) do
              {:ok, %{active: true} = principal} -> {:ok, principal}
              _ -> :error
            end

          _ ->
            :error
        end

      _ ->
        :error
    end
  end

  defp maybe_external_redirect(conn, "/" <> _ = path), do: redirect(conn, to: path)
  defp maybe_external_redirect(conn, url), do: redirect(conn, external: url)
end
