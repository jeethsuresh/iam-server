defmodule LakehouseIam.Apps.Tokens do
  @moduledoc """
  Opaque access/refresh tokens for third-party apps (hashed at rest).
  """
  import Ecto.Query

  alias LakehouseIam.Apps.Grants
  alias LakehouseIam.Repo
  alias LakehouseIam.Schema.{AppGrant, AppToken}

  @access_ttl_sec 3600
  @refresh_ttl_sec 30 * 24 * 3600

  @spec issue(AppGrant.t()) ::
          {:ok, %{access_token: String.t(), refresh_token: String.t(), expires_in: pos_integer()}}
          | {:error, term()}
  def issue(%AppGrant{} = grant) do
    access_raw = raw_token()
    refresh_raw = raw_token()
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)

    Repo.transaction(fn ->
      {:ok, _} =
        insert_token(grant.id, access_raw, :access, DateTime.add(now, @access_ttl_sec, :second))

      {:ok, _} =
        insert_token(
          grant.id,
          refresh_raw,
          :refresh,
          DateTime.add(now, @refresh_ttl_sec, :second)
        )

      %{
        access_token: access_raw,
        refresh_token: refresh_raw,
        expires_in: @access_ttl_sec,
        token_type: "Bearer"
      }
    end)
  end

  defp insert_token(grant_id, raw, kind, expires_at) do
    %AppToken{}
    |> AppToken.changeset(%{
      grant_id: grant_id,
      token_hash: hash(raw),
      kind: kind,
      expires_at: expires_at
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
        if DateTime.compare(exp, now) == :lt do
          {:error, :expired}
        else
          case Repo.get(AppGrant, token.grant_id) do
            nil -> {:error, :invalid}
            grant -> {:ok, %{grant: grant, token: token}}
          end
        end
    end
  end

  @spec refresh(String.t()) ::
          {:ok, %{access_token: String.t(), refresh_token: String.t(), expires_in: pos_integer()}}
          | {:error, atom()}
  def refresh(raw_refresh) when is_binary(raw_refresh) do
    now = DateTime.utc_now()

    case Repo.get_by(AppToken, token_hash: hash(raw_refresh), kind: :refresh) do
      nil ->
        {:error, :invalid}

      %{revoked_at: rev} when not is_nil(rev) ->
        {:error, :revoked}

      %{expires_at: exp} = token ->
        if DateTime.compare(exp, now) == :lt do
          {:error, :expired}
        else
          case Repo.get(AppGrant, token.grant_id) do
            nil ->
              {:error, :invalid}

            grant ->
              _ = revoke_token(token)
              issue(grant)
          end
        end
    end
  end

  def refresh(_), do: {:error, :invalid}

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
