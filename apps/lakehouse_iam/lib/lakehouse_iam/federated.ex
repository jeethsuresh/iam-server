defmodule LakehouseIam.Federated do
  @moduledoc """
  In-memory federated OAuth PKCE sessions and one-time authorization codes.

  App identity is the origin of `caller_url` / `redirect_url` (must match).
  """
  use GenServer

  alias LakehouseIam.Apps.{Origin, Pkce, Scopes, VerifiedDomain}
  alias LakehouseIam.Auth.CallbackURL

  defstruct sessions: %{}, codes: %{}

  @session_ttl_ms 10 * 60 * 1000
  @code_ttl_ms 5 * 60 * 1000

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  def reset! do
    GenServer.call(__MODULE__, :reset)
  end

  @doc """
  Registers a PKCE federated login attempt.

  Attrs: `:username`, `:caller_url`, `:redirect_url`, `:code_challenge`,
  `:code_challenge_method` (default `"S256"`), `:scope` (string or list),
  optional `:state`.
  """
  def register(attrs) when is_map(attrs) do
    GenServer.call(__MODULE__, {:register, attrs})
  end

  def fetch(session_id), do: GenServer.call(__MODULE__, {:fetch, session_id})
  def delete(session_id), do: GenServer.call(__MODULE__, {:delete, session_id})

  def put_code(code, payload) when is_binary(code) and is_map(payload) do
    GenServer.call(__MODULE__, {:put_code, code, payload})
  end

  def take_code(code) when is_binary(code) do
    GenServer.call(__MODULE__, {:take_code, code})
  end

  def verify_pkce(payload, verifier) do
    Pkce.verify(verifier, payload.code_challenge, payload.code_challenge_method || "S256")
  end

  @impl true
  def init(_opts) do
    {:ok, %__MODULE__{}}
  end

  @impl true
  def handle_call(:reset, _from, _state) do
    {:reply, :ok, %__MODULE__{}}
  end

  def handle_call({:fetch, session_id}, _from, state) do
    sess = Map.get(state.sessions, session_id)

    sess =
      cond do
        is_nil(sess) -> nil
        expired?(sess.expires_at) -> nil
        true -> sess
      end

    {:reply, sess, state}
  end

  def handle_call({:delete, session_id}, _from, state) do
    {:reply, :ok, %{state | sessions: Map.delete(state.sessions, session_id)}}
  end

  def handle_call({:register, attrs}, _from, state) do
    case build_session(attrs) do
      {:ok, session_id, username, sess} ->
        {:reply, {:ok, session_id, username},
         %{state | sessions: Map.put(state.sessions, session_id, sess)}}

      {:error, _} = err ->
        {:reply, err, state}
    end
  end

  def handle_call({:put_code, code, payload}, _from, state) do
    entry = Map.put(payload, :expires_at, System.system_time(:millisecond) + @code_ttl_ms)
    {:reply, :ok, %{state | codes: Map.put(state.codes, code, entry)}}
  end

  def handle_call({:take_code, code}, _from, state) do
    case Map.pop(state.codes, code) do
      {nil, _} ->
        {:reply, nil, state}

      {entry, codes} ->
        if expired?(entry.expires_at) do
          {:reply, nil, %{state | codes: codes}}
        else
          {:reply, entry, %{state | codes: codes}}
        end
    end
  end

  defp build_session(attrs) do
    username =
      (attr(attrs, :username, "username") || "")
      |> to_string()
      |> String.trim()
      |> String.downcase()

    caller_url = attr(attrs, :caller_url, "callerURL")
    redirect_url = attr(attrs, :redirect_url, "redirectURL")
    challenge = attr(attrs, :code_challenge, "codeChallenge")
    method = attr(attrs, :code_challenge_method, "codeChallengeMethod") || "S256"
    scope_raw = attr(attrs, :scope, "scope") || ""
    state = attr(attrs, :state, "state")

    with :ok <- require_username(username),
         {:ok, scopes} <- Scopes.parse(scope_raw),
         :ok <- require_binary(caller_url, "callerURL"),
         :ok <- require_binary(redirect_url, "redirectURL"),
         :ok <- CallbackURL.validate(caller_url, "callerURL"),
         :ok <- CallbackURL.validate(redirect_url, "redirectURL"),
         :ok <- require_same_origin(caller_url, redirect_url),
         {:ok, app_origin} <- Origin.from_url(redirect_url),
         :ok <- require_s256(method),
         :ok <- require_binary(challenge, "codeChallenge"),
         :ok <- VerifiedDomain.verify(%{origin: app_origin}) do
      session_id = Ecto.UUID.generate()

      sess = %{
        username: username,
        caller_url: caller_url,
        redirect_url: redirect_url,
        app_origin: app_origin,
        code_challenge: challenge,
        code_challenge_method: method,
        scopes: scopes,
        state: state,
        expires_at: System.system_time(:millisecond) + @session_ttl_ms
      }

      {:ok, session_id, username, sess}
    end
  end

  defp require_username(""), do: {:error, "Invalid username"}
  defp require_username(_), do: :ok

  defp require_binary(v, _name) when is_binary(v) and v != "", do: :ok
  defp require_binary(_, name), do: {:error, "#{name} required"}

  defp require_same_origin(a, b) do
    if Origin.same_origin?(a, b) do
      :ok
    else
      {:error, "callerURL and redirectURL must share the same origin"}
    end
  end

  defp require_s256("S256"), do: :ok
  defp require_s256(_), do: {:error, "codeChallengeMethod must be S256"}

  defp attr(map, atom_key, string_key) do
    Map.get(map, atom_key) || Map.get(map, string_key)
  end

  defp expired?(expires_at), do: System.system_time(:millisecond) > expires_at
end
