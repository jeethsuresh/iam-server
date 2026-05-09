defmodule LakehouseIam.Auth.TokenBehaviour do
  @moduledoc false

  @callback issue(username :: String.t()) :: String.t()
  @callback verify(token :: String.t()) :: {:ok, map()} | :error
end
