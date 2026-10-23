defmodule LakehouseIam.NativeBroker do
  @moduledoc "Consent-preserving, family-bound authorization for an explicitly trusted native broker."

  import Ecto.Query
  alias LakehouseIam.{Discovery, Federated, Repo}
  alias LakehouseIam.Apps.{Origin, Scopes, Tokens}
  alias LakehouseIam.Schema.{AppGrant, Session}

  @scope "native.broker"

  def origin, do: Application.get_env(:lakehouse_iam, :native_broker_origin)

  def validate_scope_origin(app_origin, redirect_url, scopes) do
    if @scope in scopes do
      if is_binary(origin()) and app_origin == origin() and
           redirect_url == origin() <> "/auth/android/callback",
        do: :ok,
        else: {:error, "native.broker requires the configured broker's exact native callback"}
    else
      :ok
    end
  end

  def authorize(raw, params) when is_binary(raw) and byte_size(raw) in 32..256 and is_map(params) do
    with {:ok, auth} <- authenticate(raw),
         {:ok, request} <- validate_request(params) do
      Repo.transaction(fn ->
        now = DateTime.utc_now()

        # Logout/refresh/token issuance serialize on this same row. A code
        # cannot outlive or create a replacement for the original login family.
        family =
          Repo.one(
            from s in Session,
              where:
                s.id == ^auth.token.session_id and s.principal_id == ^auth.grant.principal_id and
                  is_nil(s.revoked_at) and s.expires_at > ^now,
              lock: "FOR UPDATE"
          ) || Repo.rollback(:invalid_token)

        auth =
          case authenticate(raw) do
            {:ok, current} -> current
            {:error, reason} -> Repo.rollback(reason)
          end

        grant =
          Repo.one(
            from g in AppGrant,
              where: g.principal_id == ^auth.grant.principal_id and g.app_origin == ^request.app_origin,
              lock: "FOR UPDATE"
          ) || Repo.rollback(:consent_required)

        unless Scopes.covers?(grant.scopes, request.scopes), do: Repo.rollback(:consent_required)
        remaining_ms = min(DateTime.diff(family.expires_at, DateTime.utc_now(), :millisecond), 60_000)
        if remaining_ms < 1_000, do: Repo.rollback(:invalid_token)
        code = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)

        payload = %{
          grant_id: grant.id,
          session_id: family.id,
          app_origin: request.app_origin,
          redirect_url: request.redirect_url,
          scopes: request.scopes,
          code_challenge: request.code_challenge,
          code_challenge_method: "S256",
          state: request.state
        }

        case Federated.put_code(code, payload, remaining_ms) do
          :ok -> :ok
          {:error, _} -> Repo.rollback(:temporarily_unavailable)
        end

        %{
          code: code,
          state: request.state,
          issuer: Discovery.public_url(),
          app_origin: request.app_origin,
          redirect_uri: request.redirect_url,
          session_id: family.id,
          sub: grant.principal_id,
          expires_in: div(remaining_ms, 1_000)
        }
      end)
    end
  end

  def authorize(_, _), do: {:error, :invalid_token}

  defp authenticate(raw) do
    case Tokens.verify_access(raw) do
      {:ok, %{grant: grant, token: token} = auth} ->
        if is_binary(origin()) and grant.app_origin == origin() and
             is_binary(token.session_id) and is_list(token.scopes) and
             @scope in token.scopes and @scope in grant.scopes,
          do: {:ok, auth},
          else: {:error, :insufficient_scope}

      _ ->
        {:error, :invalid_token}
    end
  end

  defp validate_request(params) do
    app_origin = params["app_origin"]

    attrs = %{
      caller_url: app_origin,
      redirect_url: params["redirect_uri"],
      code_challenge: params["code_challenge"],
      code_challenge_method: params["code_challenge_method"],
      scope: params["scope"],
      state: params["state"]
    }

    with true <- is_binary(app_origin) and app_origin != origin(),
         "profile.name" <- params["scope"],
         {:ok, ^app_origin} <- Origin.from_url(app_origin),
         "S256" <- params["code_challenge_method"],
         state when is_binary(state) and byte_size(state) in 1..1024 <- params["state"],
         {:ok, request} <- Federated.validate_request(attrs),
         ["profile.name"] <- request.scopes do
      {:ok, request}
    else
      _ -> {:error, :invalid_request}
    end
  end
end
