defmodule LakehouseIam.Federated do
  @moduledoc "Postgres-backed PKCE login sessions and atomically consumed authorization codes."

  import Ecto.Query
  alias LakehouseIam.Apps.{Origin, Scopes, VerifiedDomain}
  alias LakehouseIam.Auth.CallbackURL
  alias LakehouseIam.{Identifier, Repo}
  alias LakehouseIam.Schema.FederatedEntry

  @session_ttl_ms 10 * 60 * 1000
  @code_ttl_ms 5 * 60 * 1000
  @payload_keys ~w(username domain caller_url redirect_url app_origin code_challenge code_challenge_method scopes state expires_at grant_id session_id)a

  def reset! do
    Repo.delete_all(FederatedEntry)
    :ok
  end

  def register(attrs) when is_map(attrs) do
    with {:ok, session} <- validate_request(attrs) do
      id = Ecto.UUID.generate()
      with :ok <- put_entry(id, :session, session, @session_ttl_ms),
        do: {:ok, id, session.username}
    end
  end

  @doc "Validate a request without creating a pending browser session."
  def validate_request(attrs) when is_map(attrs) do
    state = attr(attrs, :state, "state")

    with {:ok, username} <- optional_username(attr(attrs, :username, "username")),
         :ok <- validate_state(state, username),
         {:ok, scopes} <- Scopes.parse(attr(attrs, :scope, "scope") || ""),
         caller_url <- attr(attrs, :caller_url, "callerURL"),
         redirect_url <- attr(attrs, :redirect_url, "redirectURL"),
         :ok <- validate_url(caller_url, "callerURL"),
         :ok <- validate_url(redirect_url, "redirectURL"),
         true <- Origin.same_origin?(caller_url, redirect_url),
         {:ok, app_origin} <- Origin.from_url(redirect_url),
         "S256" <- attr(attrs, :code_challenge_method, "codeChallengeMethod") || "S256",
         challenge when is_binary(challenge) <- attr(attrs, :code_challenge, "codeChallenge"),
         true <- Regex.match?(~r/\A[A-Za-z0-9_-]{43}\z/, challenge),
         :ok <- LakehouseIam.NativeBroker.validate_scope_origin(app_origin, redirect_url, scopes),
         :ok <- VerifiedDomain.verify(%{origin: app_origin}) do
      session = %{
        username: username,
        domain: Identifier.domain(),
        caller_url: caller_url,
        redirect_url: redirect_url,
        app_origin: app_origin,
        code_challenge: challenge,
        code_challenge_method: "S256",
        scopes: scopes,
        state: state
      }

      {:ok, session}
    else
      false ->
        {:error,
         "callerURL and redirectURL must share the same origin; a valid S256 codeChallenge is required"}

      {:error, _} = error ->
        error

      _ ->
        {:error, "codeChallengeMethod must be S256 and codeChallenge is required"}
    end
  end

  def fetch(id) when is_binary(id) do
    case Repo.get(FederatedEntry, key(:session, id)) do
      %{data: data, expires_at: expires_at} ->
        if expires_at > now(), do: decode(data), else: nil

      _ ->
        nil
    end
  end

  def fetch(_), do: nil

  @doc "Bind an unclaimed request once to a verified local principal."
  def bind_user(id, username) when is_binary(id) and is_binary(username) do
    Repo.transaction(fn ->
      entry =
        Repo.one(from e in FederatedEntry, where: e.key == ^key(:session, id), lock: "FOR UPDATE")

      cond do
        is_nil(entry) or entry.expires_at <= now() ->
          Repo.rollback(:invalid_session)

        entry.data["username"] not in [nil, username] ->
          Repo.rollback(:username_mismatch)

        true ->
          data = Map.put(entry.data, "username", username)
          entry |> Ecto.Changeset.change(data: data) |> Repo.update!()
          decode(data)
      end
    end)
  end

  def bind_user(_, _), do: {:error, :invalid_session}

  def delete(id) do
    Repo.delete_all(from e in FederatedEntry, where: e.key == ^key(:session, id))
    :ok
  end

  def put_code(code, payload, ttl_ms \\ @code_ttl_ms),
    do: put_entry(code, :code, payload, ttl_ms)

  def take_code(code) when is_binary(code) do
    cutoff = now()
    # DELETE RETURNING is one database operation: concurrent exchanges cannot both win.
    case Repo.delete_all(
           from e in FederatedEntry,
             where: e.key == ^key(:code, code) and e.expires_at > ^cutoff,
             select: e.data
         ) do
      {1, [data]} -> decode(data)
      _ -> nil
    end
  end

  def take_code(_), do: nil

  def verify_pkce(payload, verifier) do
    LakehouseIam.Apps.Pkce.verify(verifier, payload.code_challenge, payload.code_challenge_method)
  end

  defp put_entry(id, kind, payload, ttl) do
    cutoff = now()
    Repo.delete_all(from e in FederatedEntry, where: e.expires_at <= ^cutoff)

    case Repo.insert(%FederatedEntry{
           key: key(kind, id),
           kind: kind,
           data: Map.put(payload, :expires_at, cutoff + ttl),
           expires_at: cutoff + ttl
         }) do
      {:ok, _} -> :ok
      {:error, _} -> {:error, "could not store login state"}
    end
  end

  defp decode(data) do
    Map.new(@payload_keys, fn key -> {key, Map.get(data, Atom.to_string(key))} end)
  end

  defp validate_url(url, name) when is_binary(url) and url != "",
    do: CallbackURL.validate(url, name)

  defp validate_url(_, name), do: {:error, "#{name} required"}
  defp optional_username(nil), do: {:ok, nil}
  defp optional_username(""), do: {:ok, nil}
  defp optional_username(username), do: Identifier.local_username(username)

  defp validate_state(state, _username) when is_binary(state) and byte_size(state) in 1..1024,
    do: :ok

  defp validate_state(nil, username) when is_binary(username), do: :ok
  defp validate_state(_, _), do: {:error, "state must be a nonempty string of at most 1024 bytes"}
  defp attr(attrs, atom, string), do: Map.get(attrs, atom) || Map.get(attrs, string)
  defp key(kind, id), do: :crypto.hash(:sha256, "#{kind}:#{id}") |> Base.encode16(case: :lower)
  defp now, do: System.system_time(:millisecond)
end
