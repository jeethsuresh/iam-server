defmodule LakehouseIam.Federated do
  @moduledoc """
  In-memory federated login sessions (`POST /backend/register`), mirroring iam-server.
  Ephemeral ES256 keypairs per session; lost on restart.
  """
  use GenServer

  defstruct [:sessions]

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  def reset! do
    GenServer.call(__MODULE__, :reset)
  end

  @doc """
  Registers callbacks for a federated attempt. Returns
  `{:ok, session_id, username, public_key_base64_pkix}` or `{:error, term}`.
  """
  def register(username, token_url, redirect_url) do
    GenServer.call(__MODULE__, {:register, username, token_url, redirect_url})
  end

  @doc """
  Looks up a session by id (used when completing login).
  """
  def fetch(session_id) do
    GenServer.call(__MODULE__, {:fetch, session_id})
  end

  def delete(session_id) do
    GenServer.call(__MODULE__, {:delete, session_id})
  end

  @impl true
  def init(_opts) do
    {:ok, %__MODULE__{sessions: %{}}}
  end

  @impl true
  def handle_call(:reset, _from, _state) do
    {:reply, :ok, %__MODULE__{sessions: %{}}}
  end

  def handle_call({:fetch, session_id}, _from, state) do
    {:reply, Map.get(state.sessions, session_id), state}
  end

  def handle_call({:delete, session_id}, _from, state) do
    {:reply, :ok, %{state | sessions: Map.delete(state.sessions, session_id)}}
  end

  def handle_call({:register, username, token_url, redirect_url}, _from, state) do
    u = username |> String.trim() |> String.downcase()

    if u == "" do
      {:reply, {:error, "Invalid username"}, state}
    else
      case LakehouseIam.Auth.CallbackURL.validate(token_url, "tokenURL") do
        {:error, _} = err ->
          {:reply, err, state}

        :ok ->
          case LakehouseIam.Auth.CallbackURL.validate(redirect_url, "redirectURL") do
            {:error, _} = err ->
              {:reply, err, state}

            :ok ->
              session_id = Ecto.UUID.generate()
              private_jwk = JOSE.JWK.generate_key({:ec, :"P-256"})
              public_jwk = JOSE.JWK.to_public(private_jwk)
              pkix_b64 = public_pkix_base64(public_jwk)

              sess = %{
                username: u,
                token_url: token_url,
                redirect_url: redirect_url,
                private_jwk: private_jwk
              }

              {:reply, {:ok, session_id, u, pkix_b64},
               %{state | sessions: Map.put(state.sessions, session_id, sess)}}
          end
      end
    end
  end

  defp public_pkix_base64(public_jwk) do
    pem = JOSE.JWK.to_pem(public_jwk)

    entries = :public_key.pem_decode(pem)

    {:SubjectPublicKeyInfo, der, :not_encrypted} =
      Enum.find(entries, fn e -> match?({:SubjectPublicKeyInfo, _, _}, e) end)

    Base.encode64(der)
  end
end
