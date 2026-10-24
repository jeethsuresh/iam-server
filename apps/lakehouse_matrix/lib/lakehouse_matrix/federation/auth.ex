defmodule LakehouseMatrix.Federation.Auth do
  @moduledoc "Verify X-Matrix authentication against self-signed server keys retrieved over verified HTTPS."
  alias LakehouseMatrix.{Identity, Federation.Signing, Federation.Transport}

  def verify(method, uri, content, headers, fetch \\ &Transport.get_json/2) do
    Enum.reduce_while(headers, {:error, :unauthorized}, fn header, _ ->
      with {:ok, values} <- parse(header),
           {:ok, _} <- Transport.server_name(values["origin"]),
           true <- values["destination"] == Identity.homeserver_domain(),
           true <- String.starts_with?(values["key"], "ed25519:"),
           {:ok, keys} <- fetch.(values["origin"], "/_matrix/key/v2/server"),
           {:ok, public} <- key(keys, values["origin"], values["key"]),
           signed <-
             Signing.request_object(method, uri, values["origin"], values["destination"], content),
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

  def parse("X-Matrix " <> rest) do
    entries = Regex.scan(~r/(?:\A|,)\s*([a-z_]+)="([A-Za-z0-9_.:\[\]+\/=~-]+)"\s*(?=,|\z)/, rest)
    values = Map.new(entries, fn [_, k, v] -> {k, v} end)
    reconstructed = Enum.map_join(entries, "", &hd/1) |> String.replace(~r/\s/, "")

    if map_size(values) == 4 and length(entries) == 4 and
         Enum.sort(Map.keys(values)) == ~w(destination key origin sig) and
         reconstructed == String.replace(rest, ~r/\s/, ""),
       do: {:ok, values},
       else: {:error, :invalid_header}
  end

  def parse(_), do: {:error, :invalid_header}
end
