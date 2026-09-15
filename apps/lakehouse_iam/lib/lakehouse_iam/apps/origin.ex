defmodule LakehouseIam.Apps.Origin do
  @moduledoc """
  App identity is the HTTPS (or http) origin of caller/redirect URLs.
  """

  @doc "Extract scheme://host[:port] origin from an absolute URL."
  @spec from_url(String.t()) :: {:ok, String.t()} | {:error, String.t()}
  def from_url(url) when is_binary(url) do
    case URI.parse(url) do
      %URI{scheme: scheme, host: host} = uri
      when scheme in ["http", "https"] and is_binary(host) and host != "" ->
        origin =
          case uri.port do
            nil -> "#{scheme}://#{host}"
            port ->
              default = if scheme == "https", do: 443, else: 80

              if port == default do
                "#{scheme}://#{host}"
              else
                "#{scheme}://#{host}:#{port}"
              end
          end

        {:ok, String.downcase(origin)}

      _ ->
        {:error, "invalid URL for origin"}
    end
  end

  @spec same_origin?(String.t(), String.t()) :: boolean()
  def same_origin?(url_a, url_b) do
    with {:ok, a} <- from_url(url_a),
         {:ok, b} <- from_url(url_b) do
      a == b
    else
      _ -> false
    end
  end
end
