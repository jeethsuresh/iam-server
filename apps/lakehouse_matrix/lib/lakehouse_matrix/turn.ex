defmodule LakehouseMatrix.Turn do
  @moduledoc "Short-lived, per-user coturn REST credentials for standard Matrix clients."
  alias LakehouseMatrix.Identity

  def credentials(username, now \\ System.system_time(:second)) do
    case Application.get_env(:lakehouse_matrix, :turn) do
      %{uris: uris, secret: secret, ttl: ttl} = config ->
        if valid_config?(config) do
          user = "#{now + ttl}:#{Identity.user_id(username)}"

          {:ok,
           %{
             "username" => user,
             "password" => Base.encode64(:crypto.mac(:hmac, :sha, secret, user)),
             "ttl" => ttl,
             "uris" => uris
           }}
        else
          {:error, :unavailable}
        end

      nil ->
        {:error, :not_found}

      _ ->
        {:error, :unavailable}
    end
  end

  def valid_config?(%{uris: uris, secret: secret, ttl: ttl}),
    do:
      is_binary(secret) and byte_size(secret) >= 32 and is_integer(ttl) and ttl in 60..86_400 and
        is_list(uris) and length(uris) in 1..16 and Enum.all?(uris, &valid_uri?/1)

  def valid_config?(_), do: false

  defp valid_uri?(uri) when is_binary(uri) and byte_size(uri) <= 2048 do
    with %URI{
           scheme: scheme,
           path: authority,
           query: query,
           host: nil,
           userinfo: nil,
           fragment: nil
         } <- URI.parse(uri),
         true <-
           scheme in ~w(turn turns) and is_binary(authority) and
             query in [nil, "transport=udp", "transport=tcp"],
         %URI{host: host, port: port, userinfo: nil, path: path, fragment: nil} <-
           URI.parse("https://" <> authority),
         true <-
           is_binary(host) and byte_size(host) > 0 and port in 1..65535 and path in [nil, ""] do
      not String.match?(authority, ~r/[\s\x00-\x1f\x7f]/u)
    else
      _ -> false
    end
  rescue
    _ -> false
  end

  defp valid_uri?(_), do: false
end
