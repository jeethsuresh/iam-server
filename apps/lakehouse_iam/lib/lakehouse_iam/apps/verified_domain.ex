defmodule LakehouseIam.Apps.VerifiedDomain do
  @moduledoc """
  Scaffold for future verified app domains.

  Planned: app origin publishes a public key via DNS TXT or HTTPS well-known,
  and login requests carry a signature over caller/redirect/challenge. Not
  enforced yet — `verify/1` always returns `:ok`.
  """

  @type proof :: %{
          optional(:origin) => String.t(),
          optional(:signature) => String.t(),
          optional(:public_key) => String.t(),
          optional(:payload) => String.t()
        }

  @doc "Future: validate DNS/HTTPS pubkey + signed request. Currently a no-op."
  @spec verify(proof()) :: :ok | {:error, String.t()}
  def verify(_proof), do: :ok
end
