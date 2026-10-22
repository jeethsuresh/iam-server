defmodule LakehouseWeb.IamAuth do
  @moduledoc """
  Shared login/register logic for JSON API and HTML form flows.
  """
  alias LakehouseIam.Accounts
  alias LakehouseIam.Apps.{Grants, Scopes}
  alias LakehouseIam.Auth.{OAuth, Sessions, Token}
  alias LakehouseIam.Federated

  @type error :: {:error, Plug.Conn.status(), term()}

  @spec standard_login(String.t(), String.t()) :: {:ok, String.t()} | error()
  def standard_login(username, password) do
    with :ok <- Accounts.validate_login_form(username, password) do
      u = Accounts.normalize_username(username)

      case Accounts.fetch_user(u) do
        :error ->
          {:error, :unauthorized, "Invalid credentials."}

        {:ok, principal} ->
          cond do
            not Accounts.password_valid?(u, password) ->
              {:error, :unauthorized, "Invalid credentials."}

            principal.active != true ->
              {:error, :unauthorized, "Invalid credentials."}

            true ->
              case Token.issue(u) do
                token when is_binary(token) -> {:ok, token}
                _ -> {:error, :internal_server_error, "Could not generate token."}
              end
          end
      end
    else
      {:error, msg} -> {:error, :bad_request, msg}
    end
  end

  @doc """
  Federated PKCE login: authenticate, then consent or issue authorization code redirect.
  Returns `{:ok, %{redirect: url, user_jwt: jwt}}`.
  """
  @spec federated_login(String.t(), String.t(), String.t()) ::
          {:ok, %{redirect: String.t(), user_jwt: String.t()}} | error()
  def federated_login(username, password, session_id, opts \\ [])
      when is_binary(session_id) and session_id != "" do
    with :ok <- Accounts.validate_login_form(username, password) do
      u = Accounts.normalize_username(username)

      cond do
        not Accounts.user_exists?(u) ->
          {:error, :not_found, %{error: "user_not_found"}}

        not Accounts.password_valid?(u, password) ->
          {:error, :unauthorized, "Invalid credentials."}

        match?({:ok, %{active: false}}, Accounts.fetch_user(u)) ->
          {:error, :unauthorized, "Invalid credentials."}

        true ->
          case Accounts.fetch_user(u) do
            {:ok, principal} -> authenticated_federated(principal, session_id, opts)
            :error -> {:error, :not_found, %{error: "user_not_found"}}
          end
      end
    else
      {:error, msg} -> {:error, :bad_request, msg}
    end
  end

  defp authenticated_federated(principal, session_id, opts) do
    case Keyword.get(opts, :session_kind) do
      kind when kind in [:browser, :api] ->
        with {:ok, _} <- Federated.bind_user(session_id, principal.username),
             {:ok, bundle} <- Sessions.issue(principal.username, kind) do
          {:ok, claims} = Token.verify(bundle.token)

          case continue_federated(principal, session_id,
                 session_id: claims["sid"],
                 user_jwt: bundle.token
               ) do
            {:ok, payload} ->
              {:ok, Map.put(payload, :session_bundle, bundle)}

            error ->
              Sessions.revoke(bundle.refresh_token, kind)
              error
          end
        else
          _ -> {:error, :bad_request, "Session ID does not exist or has expired."}
        end

      _ ->
        continue_federated(principal, session_id)
    end
  end

  @doc "Continue federated flow for an already-authenticated principal."
  def continue_federated(principal, session_id, opts \\ []) do
    case Federated.bind_user(session_id, principal.username) do
      {:ok, sess} ->
        user_jwt = Keyword.get(opts, :user_jwt) || Token.issue(principal.username)
        grant = Grants.get(principal.id, sess.app_origin)

        cond do
          skip_consent?(grant, sess.scopes) ->
            finish_with_code(
              sess,
              principal,
              session_id,
              grant.room_mode,
              grant.room_ids,
              user_jwt,
              Keyword.get(opts, :session_id)
            )

          Keyword.get(opts, :silent, false) ->
            {:error, :consent_required, "Application consent is required."}

          true ->
            {:ok,
             %{
               redirect: "/oauth/consent?sessionID=#{URI.encode_www_form(session_id)}",
               user_jwt: user_jwt
             }}
        end

      {:error, :username_mismatch} ->
        {:error, :unauthorized, "Invalid session ID."}

      {:error, _} ->
        {:error, :bad_request, "Session ID does not exist or has expired."}
    end
  end

  def login_path(username \\ nil, session_id \\ nil) do
    query = %{}

    query =
      if is_binary(username) and username != "",
        do: Map.put(query, "username", username),
        else: query

    query =
      if is_binary(session_id) and session_id != "",
        do: Map.put(query, "sessionID", session_id),
        else: query

    if map_size(query) == 0, do: "/", else: "/?" <> URI.encode_query(query)
  end

  def registration_path(session_id) when is_binary(session_id) and session_id != "",
    do: "/register?" <> URI.encode_query(%{"sessionID" => session_id})

  def registration_path(_), do: "/register"

  def registration_session(session_id, _username) when session_id in [nil, ""], do: :ok

  def registration_session(session_id, username) when is_binary(username) do
    case Federated.fetch(session_id) do
      nil ->
        {:error, :bad_request, "Application login session has expired. Start again from the app."}

      %{username: expected} ->
        if expected in [nil, Accounts.normalize_username(username || "")],
          do: :ok,
          else: {:error, :bad_request, "Register the username requested by this application."}
    end
  end

  def registration_session(_, _), do: {:error, :bad_request, "username is required"}

  defp skip_consent?(nil, _), do: false

  defp skip_consent?(grant, scopes) do
    Scopes.covers?(grant.scopes, scopes) and
      (not needs_rooms?(scopes) or grant.room_mode == :all)
  end

  defp needs_rooms?(scopes), do: "chats.read" in scopes or "chats.write" in scopes

  defp finish_with_code(sess, principal, session_id, room_mode, room_ids, user_jwt, family_id) do
    case OAuth.issue_code_redirect(sess, principal.id, room_mode, room_ids, session_id: family_id) do
      {:ok, redirect} ->
        _ = Federated.delete(session_id)
        {:ok, %{redirect: redirect, user_jwt: user_jwt}}

      {:error, _} ->
        {:error, :internal_server_error, "Could not issue authorization code."}
    end
  end

  @spec register(String.t(), String.t(), term()) ::
          {:ok, LakehouseIam.Schema.Principal.t()} | error()
  def register(username, password, registration_key) do
    with :ok <- LakehouseIam.Registration.authorize(registration_key) do
      create_account(username, password)
    else
      {:error, message} -> {:error, :forbidden, message}
    end
  end

  defp create_account(username, password) when is_binary(username) and is_binary(password) do
    case Accounts.register_user(username, password) do
      {:ok, principal} ->
        {:ok, principal}

      {:error, %Ecto.Changeset{} = cs} ->
        {:error, :bad_request, format_changeset(cs)}

      {:error, bin} when is_binary(bin) ->
        {:error, :bad_request, bin}
    end
  end

  defp create_account(_, _), do: {:error, :bad_request, "username and password are required"}

  defp format_changeset(cs) do
    Ecto.Changeset.traverse_errors(cs, fn {msg, opts} ->
      Enum.reduce(opts, msg, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
    |> Enum.map_join("; ", fn {k, v} -> "#{k} #{Enum.join(v, ", ")}" end)
  end
end
