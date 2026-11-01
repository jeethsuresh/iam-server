defmodule LakehouseMatrix.Discovery do
  @moduledoc "Public Matrix transport address, independent of the signed homeserver identity."

  def public_url do
    (Application.get_env(:lakehouse_matrix, :public_url) || LakehouseIam.Discovery.public_url())
    |> String.trim_trailing("/")
  end

  def server_address do
    uri = URI.parse(public_url())
    host = if String.contains?(uri.host, ":"), do: "[#{uri.host}]", else: uri.host
    "#{host}:#{uri.port}"
  end
end
