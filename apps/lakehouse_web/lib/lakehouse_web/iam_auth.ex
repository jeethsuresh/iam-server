defmodule LakehouseWeb.IamAuth do
  @moduledoc """
  Shared login/register logic for JSON API and HTML form flows.
  """
  alias LakehouseIam.Accounts
  alias LakehouseIam.Auth.{CallbackURL, FederatedSigner, Token}
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

  @spec federated_login(String.t(), String.t(), String.t()) ::
          {:ok, %{redirect: String.t()}} | error()
  def federated_login(username, password, session_id)
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
          complete_federated(u, session_id)
      end
    else
      {:error, msg} -> {:error, :bad_request, msg}
    end
  end

  defp complete_federated(login_username, session_id) do
    case Federated.fetch(session_id) do
      nil ->
        {:error, :internal_server_error, "Session ID does not exist."}

      sess ->
        if sess.username != login_username do
          {:error, :unauthorized, "Invalid session ID."}
        else
          with :ok <- CallbackURL.validate(sess.token_url, "tokenURL"),
               :ok <- CallbackURL.validate(sess.redirect_url, "redirectURL") do
            jwt = FederatedSigner.sign(sess.private_jwk, login_username, session_id)
            body = %{sessionID: session_id, token: jwt}

            case Req.post(sess.token_url, json: body, receive_timeout: 10_000) do
              {:ok, %Req.Response{status: 200}} ->
                redirect_to = merge_session_query(sess.redirect_url, session_id)
                _ = Federated.delete(session_id)
                {:ok, %{redirect: redirect_to}}

              {:ok, %Req.Response{status: status}} ->
                {:error, :internal_server_error, "Could not validate session ID: #{status}"}

              {:error, _} ->
                {:error, :internal_server_error, "Could not send request."}
            end
          else
            {:error, msg} -> {:error, :bad_request, msg}
          end
        end
    end
  end

  defp merge_session_query(redirect_url, session_id) do
    uri = URI.parse(redirect_url)
    q = URI.decode_query(uri.query || "")
    merged = Map.put(q, "sessionID", session_id)
    %URI{uri | query: URI.encode_query(merged)} |> URI.to_string()
  end

  @spec register(String.t(), String.t()) :: {:ok, LakehouseIam.Schema.Principal.t()} | error()
  def register(username, password) do
    case Accounts.register_user(username, password) do
      {:ok, principal} ->
        {:ok, principal}

      {:error, %Ecto.Changeset{} = cs} ->
        {:error, :bad_request, format_changeset(cs)}

      {:error, bin} when is_binary(bin) ->
        {:error, :bad_request, bin}
    end
  end

  defp format_changeset(cs) do
    Ecto.Changeset.traverse_errors(cs, fn {msg, opts} ->
      Enum.reduce(opts, msg, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
    |> inspect()
  end
end
