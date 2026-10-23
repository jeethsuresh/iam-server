defmodule LakehouseIam.Apps.Tokens do
  @moduledoc """
  Opaque access/refresh tokens for third-party apps (hashed at rest).
  """
  import Ecto.Query

  alias LakehouseIam.Apps.{Grants, Scopes}
  alias LakehouseIam.Repo
  alias LakehouseIam.Schema.{AppGrant, AppToken, Principal, Session}

  @access_ttl_sec 3600
  @refresh_ttl_sec 30 * 24 * 3600

  @spec issue(AppGrant.t()) ::
          {:ok, %{access_token: String.t(), refresh_token: String.t(), expires_in: pos_integer()}}
          | {:error, term()}
  def issue(grant, session_id \\ nil, opts \\ [])

  def issue(%AppGrant{} = grant, session_id, opts) do
    Repo.transaction(fn ->
      now = DateTime.utc_now() |> DateTime.truncate(:microsecond)

      scopes = Keyword.get(opts, :scopes, grant.scopes)

      unless is_list(scopes) and Scopes.covers?(grant.scopes, scopes),
        do: Repo.rollback(:invalid_scope)

      family =
        if session_id do
          Repo.one(
            from s in Session,
              where:
                s.id == ^session_id and s.principal_id == ^grant.principal_id and
                  is_nil(s.revoked_at) and s.expires_at > ^now,
              lock: "FOR UPDATE"
          ) || Repo.rollback(:invalid_session)
        end

      principal = Repo.get(Principal, grant.principal_id)
      unless principal && principal.active, do: Repo.rollback(:invalid_session)
      access_raw = raw_token()
      refresh_raw = raw_token()
      access_expiry = bounded_expiry(now, @access_ttl_sec, family)
      refresh_expiry = bounded_expiry(now, @refresh_ttl_sec, family)
      {:ok, _} = insert_token(grant.id, access_raw, :access, access_expiry, session_id, scopes)
      {:ok, _} = insert_token(grant.id, refresh_raw, :refresh, refresh_expiry, session_id, scopes)

      result = %{
        access_token: access_raw,
        refresh_token: refresh_raw,
        expires_in: max(DateTime.diff(access_expiry, now, :second), 0),
        token_type: "Bearer",
        scope: Enum.join(scopes, " ")
      }

      if family do
        raw = raw_token()
        {:ok, _} = insert_token(grant.id, raw, :session_check, family.expires_at, family.id, [])

        Map.merge(result, %{
          session_check_token: raw,
          session_check_expires_in: max(DateTime.diff(family.expires_at, now, :second), 0),
          session_id: family.id
        })
      else
        result
      end
    end)
  end

  defp bounded_expiry(now, seconds, nil), do: DateTime.add(now, seconds, :second)

  defp bounded_expiry(now, seconds, family) do
    expiry = DateTime.add(now, seconds, :second)
    if DateTime.compare(expiry, family.expires_at) == :lt, do: expiry, else: family.expires_at
  end

  defp insert_token(grant_id, raw, kind, expires_at, session_id, scopes) do
    %AppToken{}
    |> AppToken.changeset(%{
      grant_id: grant_id,
      session_id: session_id,
      token_hash: hash(raw),
      kind: kind,
      expires_at: expires_at,
      scopes: scopes
    })
    |> Repo.insert()
  end

  @spec verify_access(String.t()) ::
          {:ok, %{grant: AppGrant.t(), token: AppToken.t()}} | {:error, atom()}
  def verify_access(raw) when is_binary(raw) do
    now = DateTime.utc_now()

    case Repo.get_by(AppToken, token_hash: hash(raw), kind: :access) do
      nil ->
        {:error, :invalid}

      %{revoked_at: rev} when not is_nil(rev) ->
        {:error, :revoked}

      %{expires_at: exp} = token ->
        if DateTime.compare(exp, now) != :gt do
          {:error, :expired}
        else
          case Repo.get(AppGrant, token.grant_id) do
            nil ->
              {:error, :invalid}

            grant ->
              if valid_family?(token, grant),
                do: {:ok, %{grant: grant, token: token}},
                else: {:error, :revoked}
          end
        end
    end
  end

  @spec refresh(String.t()) ::
          {:ok, %{access_token: String.t(), refresh_token: String.t(), expires_in: pos_integer()}}
          | {:error, atom()}
  def refresh(raw_refresh) when is_binary(raw_refresh) do
    Repo.transaction(fn ->
      token =
        Repo.one(
          from t in AppToken,
            where: t.token_hash == ^hash(raw_refresh) and t.kind == :refresh,
            lock: "FOR UPDATE"
        )

      case token do
        nil ->
          Repo.rollback(:invalid)

        %{revoked_at: rev} when not is_nil(rev) ->
          Repo.rollback(:revoked)

        token ->
          if DateTime.compare(token.expires_at, DateTime.utc_now()) != :gt,
            do: Repo.rollback(:expired)

          grant = Repo.get(AppGrant, token.grant_id) || Repo.rollback(:invalid)
          {:ok, _} = revoke_token(token)

          case issue(grant, token.session_id, scopes: effective_scopes(token, grant)) do
            {:ok, bundle} -> bundle
            {:error, reason} -> Repo.rollback(reason)
          end
      end
    end)
  end

  def refresh(_), do: {:error, :invalid}

  @doc "Legacy credentials cannot inherit delegation when a consent grant is upgraded."
  def effective_scopes(%AppToken{scopes: nil}, grant),
    do: Enum.reject(grant.scopes, &(&1 in ~w(native.broker groups.join spaces.channels friends.read friends.manage contacts.read contacts.manage)))

  def effective_scopes(%AppToken{scopes: scopes}, grant),
    do: Enum.filter(scopes, &(&1 in grant.scopes))

  @doc "A status-only credential; it never grants profile or application data access."
  def check_session(raw) when is_binary(raw) and byte_size(raw) in 32..256 do
    now = DateTime.utc_now()

    result =
      Repo.one(
        from t in AppToken,
          join: g in AppGrant,
          on: g.id == t.grant_id,
          join: s in Session,
          on: s.id == t.session_id and s.principal_id == g.principal_id,
          join: p in Principal,
          on: p.id == g.principal_id,
          where:
            t.kind == :session_check and t.token_hash == ^hash(raw) and is_nil(t.revoked_at) and
              t.expires_at > ^now and is_nil(s.revoked_at) and s.expires_at > ^now and
              p.active == true,
          select: %{
            sub: p.id,
            app_origin: g.app_origin,
            session_id: s.id,
            expires_at: s.expires_at
          }
      )

    case result do
      nil ->
        {:error, :invalid}

      %{expires_at: expiry} = status ->
        {:ok,
         status
         |> Map.delete(:expires_at)
         |> Map.merge(%{
           active: true,
           iss: LakehouseIam.Discovery.public_url(),
           exp: DateTime.to_unix(expiry)
         })}
    end
  end

  def check_session(_), do: {:error, :invalid}

  defp valid_family?(token, grant) do
    case Repo.get(Principal, grant.principal_id) do
      %{active: true, username: username} ->
        is_nil(token.session_id) or LakehouseIam.Auth.Sessions.active?(token.session_id, username)

      _ ->
        false
    end
  end

  @spec revoke_grant_tokens(Ecto.UUID.t()) :: :ok
  def revoke_grant_tokens(grant_id) do
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)

    from(t in AppToken, where: t.grant_id == ^grant_id and is_nil(t.revoked_at))
    |> Repo.update_all(set: [revoked_at: now])

    :ok
  end

  defp revoke_token(%AppToken{} = token) do
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)
    token |> AppToken.changeset(%{revoked_at: now}) |> Repo.update()
  end

  def hash(raw), do: :crypto.hash(:sha256, raw) |> Base.encode16(case: :lower)

  defp raw_token do
    :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
  end

  @doc "Revoke grant and all tokens."
  def revoke_app(principal_id, app_origin) do
    case Grants.get(principal_id, app_origin) do
      nil ->
        {:error, :not_found}

      grant ->
        _ = revoke_grant_tokens(grant.id)
        Grants.revoke(grant.id)
    end
  end
end
