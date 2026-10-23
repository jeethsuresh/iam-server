defmodule LakehouseIam.Auth.Sessions do
  @moduledoc "Revocable first-party sessions with hashed, rotating refresh credentials."
  import Ecto.Query
  alias LakehouseIam.{Accounts, Repo}
  alias LakehouseIam.Auth.Token
  alias LakehouseIam.Schema.{Principal, RefreshToken, Session}

  @lifetime_seconds 30 * 24 * 3600
  @browser_grace_seconds 5

  def issue(username, kind) when kind in [:browser, :api] do
    with {:ok, %{active: true} = principal} <- Accounts.fetch_user(username) do
      Repo.transaction(fn ->
        now = now()
        Repo.delete_all(from s in Session, where: s.expires_at <= ^now)

        session =
          Repo.insert!(%Session{
            principal_id: principal.id,
            kind: kind,
            expires_at: DateTime.add(now, @lifetime_seconds, :second)
          })

        raw = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
        Repo.insert!(%RefreshToken{session_id: session.id, token_hash: hash(raw)})
        bundle(session, principal.username, raw)
      end)
    else
      _ -> {:error, :invalid}
    end
  end

  def rotate(raw, kind)
      when is_binary(raw) and byte_size(raw) in 32..256 and kind in [:browser, :api] do
    result =
      Repo.transaction(fn ->
        case Repo.get_by(RefreshToken, token_hash: hash(raw)) do
          nil ->
            {:error, :invalid}

          initial ->
            # All rotations/revocations of a family serialize on its session row.
            session =
              Repo.one(from s in Session, where: s.id == ^initial.session_id, lock: "FOR UPDATE")

            token = Repo.get(RefreshToken, initial.id)
            principal = session && Repo.get(Principal, session.principal_id)

            cond do
              not valid?(session, principal, kind) or is_nil(token) ->
                {:error, :invalid}

              is_nil(token.used_at) ->
                next = replacement(raw)
                Repo.insert!(%RefreshToken{session_id: session.id, token_hash: hash(next)})

                token
                |> Ecto.Changeset.change(used_at: now(), replacement_hash: hash(next))
                |> Repo.update!()

                {:ok, bundle(session, principal.username, next)}

              kind == :browser ->
                case current_replacement(token, raw, 0) do
                  {:ok, next} -> {:ok, bundle(session, principal.username, next)}
                  :error -> revoke_reused(session)
                end

              true ->
                revoke_reused(session)
            end
        end
      end)

    # Reuse revocation must commit even though the credential is rejected.
    case result do
      {:ok, value} -> value
      {:error, reason} -> {:error, reason}
    end
  end

  def rotate(_, _), do: {:error, :invalid}

  def active?(id, username) do
    with {:ok, id} <- Ecto.UUID.cast(id) do
      cutoff = now()

      Repo.exists?(
        from s in Session,
          join: p in Principal,
          on: p.id == s.principal_id,
          where:
            s.id == ^id and p.username == ^username and p.active == true and
              is_nil(s.revoked_at) and s.expires_at > ^cutoff
      )
    else
      _ -> false
    end
  end

  def revoke(raw, kind) when is_binary(raw) and kind in [:browser, :api] do
    case Repo.get_by(RefreshToken, token_hash: hash(raw)) do
      nil ->
        :ok

      token ->
        timestamp = now()

        Repo.update_all(
          from(s in Session,
            where: s.id == ^token.session_id and s.kind == ^kind and is_nil(s.revoked_at)
          ),
          set: [revoked_at: timestamp]
        )

        :ok
    end
  end

  def revoke(_, _), do: :ok

  def revoke_access(raw) when is_binary(raw) do
    case Token.verify(raw) do
      {:ok, %{"sid" => id}} ->
        timestamp = now()

        Repo.update_all(from(s in Session, where: s.id == ^id and is_nil(s.revoked_at)),
          set: [revoked_at: timestamp]
        )

        :ok

      _ ->
        :ok
    end
  end

  def revoke_access(_), do: :ok

  def revoke_for_principal(id) do
    timestamp = now()

    Repo.update_all(from(s in Session, where: s.principal_id == ^id and is_nil(s.revoked_at)),
      set: [revoked_at: timestamp]
    )

    :ok
  end

  defp valid?(
         %Session{kind: kind, revoked_at: nil, expires_at: expiry},
         %Principal{active: true},
         kind
       ),
       do: DateTime.compare(expiry, now()) == :gt

  defp valid?(_, _, _), do: false

  # Parallel browser requests can receive the same replacement for five seconds.
  # The raw replacement is derived with a server key; only hashes are persisted.
  defp current_replacement(%{used_at: used_at} = token, raw, depth) when depth < 8 do
    if DateTime.diff(now(), used_at, :second) in 0..@browser_grace_seconds do
      next = replacement(raw)

      case Repo.get_by(RefreshToken,
             token_hash: token.replacement_hash,
             session_id: token.session_id
           ) do
        %{token_hash: digest, used_at: nil} when digest == token.replacement_hash ->
          if hash(next) == digest, do: {:ok, next}, else: :error

        %RefreshToken{} = child ->
          if hash(next) == child.token_hash,
            do: current_replacement(child, next, depth + 1),
            else: :error

        _ ->
          :error
      end
    else
      :error
    end
  end

  defp current_replacement(_, _, _), do: :error

  defp revoke_reused(session) do
    session |> Ecto.Changeset.change(revoked_at: now()) |> Repo.update!()
    {:error, :reused}
  end

  defp bundle(session, username, raw) do
    remaining = max(DateTime.diff(session.expires_at, now(), :second), 0)
    ttl = min(Application.fetch_env!(:lakehouse_iam, :token_ttl_seconds), remaining)

    %{
      token:
        Token.issue(username,
          session_id: session.id,
          session_expires_at: DateTime.to_unix(session.expires_at),
          expires_in: ttl
        ),
      refresh_token: raw,
      expires_in: ttl,
      refresh_expires_in: remaining,
      token_type: "Bearer"
    }
  end

  defp replacement(raw),
    do:
      :crypto.mac(:hmac, :sha256, Application.fetch_env!(:lakehouse_iam, :jwt_secret), [
        "iam-refresh-rotation:v1:",
        raw
      ])
      |> Base.url_encode64(padding: false)

  def hash(raw), do: :crypto.hash(:sha256, raw) |> Base.encode16(case: :lower)
  defp now, do: DateTime.utc_now() |> DateTime.truncate(:microsecond)
end
