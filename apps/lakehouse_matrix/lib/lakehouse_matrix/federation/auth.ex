defmodule LakehouseMatrix.Federation.Auth do
  @moduledoc "Verify X-Matrix authentication against self-signed server keys retrieved over verified HTTPS."
  alias LakehouseMatrix.{Identity, Federation.Signing, Federation.Transport, Federation.Keyring}

  def verify(method, uri, content, headers, fetch \\ &Transport.get_json/2) do
    Keyring.with_cache(fn ->
      Enum.reduce_while(headers, {:error, :unauthorized}, fn header, _ ->
        with {:ok, values} <- parse(header),
             {:ok, _} <- Transport.server_name(values["origin"]),
             destination <- values["destination"] || Identity.homeserver_domain(),
             true <- destination == Identity.homeserver_domain(),
             true <- String.starts_with?(values["key"], "ed25519:"),
             {:ok, public} <-
               Keyring.key(
                 values["origin"],
                 values["key"],
                 System.system_time(:millisecond),
                 fetch
               ),
             signed <-
               Signing.request_object(
                 method,
                 uri,
                 values["origin"],
                 destination,
                 content
               ),
             signed <-
               Map.put(signed, "signatures", %{
                 values["origin"] => %{values["key"] => values["sig"]}
               }),
             true <- Signing.verify(signed, public, values["key"], values["origin"]) do
          {:halt, {:ok, values["origin"]}}
        else
          _ -> {:cont, {:error, :unauthorized}}
        end
      end)
    end)
  rescue
    _ -> {:error, :unauthorized}
  end

  def key(keys, origin, id) do
    with ^origin <- keys["server_name"],
         until when is_integer(until) <- keys["valid_until_ts"],
         true <- until > System.system_time(:millisecond),
         encoded when is_binary(encoded) <- get_in(keys, ["verify_keys", id, "key"]),
         {:ok, public} <- Base.decode64(encoded, padding: false),
         true <- byte_size(public) == 32,
         true <- Signing.verify(keys, public, id, origin) do
      {:ok, public}
    else
      _ -> {:error, :invalid_key}
    end
  end

  def parse(header) when is_binary(header) do
    with [_, rest] <- Regex.run(~r/\AX-Matrix[ \t]+(.+)\z/i, header) do
      entries =
        Regex.scan(
          ~r/(?:\A|,)[ \t]*([a-z_]+)[ \t]*=[ \t]*("(?:[^"\\\r\n]|\\[\x20-\x7e])*"|[!#$%&'*+.^_`|~0-9A-Za-z:-]+)[ \t]*(?=,|\z)/i,
          rest
        )

      values = Map.new(entries, fn [_, k, v] -> {String.downcase(k), unquote_value(v)} end)
      keys = Map.keys(values) |> Enum.sort()

      if length(entries) == map_size(values) and
           keys in [~w(key origin sig), ~w(destination key origin sig)] and
           Enum.map_join(entries, "", &hd/1) == rest,
         do: {:ok, values},
         else: {:error, :invalid_header}
    else
      _ -> {:error, :invalid_header}
    end
  end

  def parse(_), do: {:error, :invalid_header}

  defp unquote_value("\"" <> _ = value),
    do: value |> String.slice(1..-2//1) |> String.replace(~r/\\(.)/, "\\1")

  defp unquote_value(value), do: value
end
