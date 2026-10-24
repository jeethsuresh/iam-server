defmodule LakehouseMatrix.Federation.Signing do
  @moduledoc "Matrix canonical JSON and Ed25519 signatures (separate from Gravitas IAM JWTs)."
  alias LakehouseMatrix.Identity
  @max_integer 9_007_199_254_740_991

  def canonical(value), do: value |> canonical_iodata() |> IO.iodata_to_binary()

  defp canonical_iodata(map) when is_map(map) do
    unless Enum.all?(Map.keys(map), &is_binary/1),
      do: raise(ArgumentError, "Matrix JSON object keys must be strings")

    entries =
      map
      |> Enum.sort_by(&elem(&1, 0))
      |> Enum.map(fn {key, value} -> [Jason.encode!(key), ":", canonical_iodata(value)] end)

    ["{", Enum.intersperse(entries, ","), "}"]
  end

  defp canonical_iodata(list) when is_list(list),
    do: ["[", Enum.intersperse(Enum.map(list, &canonical_iodata/1), ","), "]"]

  defp canonical_iodata(n) when is_integer(n) and n >= -@max_integer and n <= @max_integer,
    do: Integer.to_string(n)

  defp canonical_iodata(value) when is_binary(value) or is_boolean(value) or is_nil(value),
    do: Jason.encode!(value)

  defp canonical_iodata(_), do: raise(ArgumentError, "Value is outside Matrix canonical JSON")

  def config do
    with seed when is_binary(seed) <- Application.get_env(:lakehouse_matrix, :signing_key),
         {:ok, raw} <- Base.decode64(seed, padding: false),
         true <- byte_size(raw) == 32,
         key_id <- Application.get_env(:lakehouse_matrix, :signing_key_id, "ed25519:gravitas1"),
         true <- is_binary(key_id) and Regex.match?(~r/\Aed25519:[A-Za-z0-9_]+\z/, key_id) do
      {:ok, raw, key_id}
    else
      _ -> {:error, :not_configured}
    end
  end

  def public_key(seed) do
    {public, _} = :crypto.generate_key(:eddsa, :ed25519, seed)
    public
  end

  def sign(object, seed, key_id, server) do
    bytes = canonical(Map.drop(object, ["signatures", "unsigned"]))

    signature =
      :crypto.sign(:eddsa, :none, bytes, [seed, :ed25519]) |> Base.encode64(padding: false)

    signatures =
      Map.update(
        object["signatures"] || %{},
        server,
        %{key_id => signature},
        &Map.put(&1, key_id, signature)
      )

    Map.put(object, "signatures", signatures)
  end

  def verify(object, public, key_id, server) do
    with signature when is_binary(signature) <- get_in(object, ["signatures", server, key_id]),
         {:ok, raw} <- Base.decode64(signature, padding: false),
         true <- byte_size(raw) == 64,
         true <- byte_size(public) == 32 do
      :crypto.verify(
        :eddsa,
        :none,
        canonical(Map.drop(object, ["signatures", "unsigned"])),
        raw,
        [public, :ed25519]
      )
    else
      _ -> false
    end
  rescue
    _ -> false
  end

  def server_keys do
    with {:ok, seed, key_id} <- config() do
      {:ok,
       sign(
         %{
           "server_name" => Identity.homeserver_domain(),
           "valid_until_ts" => System.system_time(:millisecond) + 86_400_000,
           "verify_keys" => %{
             key_id => %{"key" => public_key(seed) |> Base.encode64(padding: false)}
           },
           "old_verify_keys" => %{}
         },
         seed,
         key_id,
         Identity.homeserver_domain()
       )}
    end
  end

  def authorization(method, uri, destination, content \\ nil) do
    with {:ok, _} <- LakehouseMatrix.Federation.Transport.server_name(destination),
         {:ok, seed, key_id} <- config() do
      origin = Identity.homeserver_domain()

      object =
        request_object(method, uri, origin, destination, content) |> sign(seed, key_id, origin)

      sig = object["signatures"][origin][key_id]

      {:ok,
       ~s(X-Matrix origin="#{origin}",destination="#{destination}",key="#{key_id}",sig="#{sig}")}
    end
  end

  def request_object(method, uri, origin, destination, nil),
    do: %{"method" => method, "uri" => uri, "origin" => origin, "destination" => destination}

  def request_object(method, uri, origin, destination, content),
    do: Map.put(request_object(method, uri, origin, destination, nil), "content", content)
end
