defmodule LakehouseIam.Protocols.JsonSchema do
  @moduledoc "Bounded JSON Schema subset for PCR v1. Unsupported keywords fail closed."
  @keys ~w(type properties required additionalProperties items enum minLength maxLength pattern minimum maximum minItems maxItems description)
  @types ~w(object array string integer number boolean null)

  def schema?(s, depth \\ 0)

  def schema?(s, depth) when is_map(s) and depth < 12 do
    props = Map.get(s, "properties", %{})
    required = Map.get(s, "required", [])

    s["type"] in @types and Enum.all?(Map.keys(s), &(&1 in @keys)) and
      is_map(props) and map_size(props) <= 64 and
      Enum.all?(props, fn {key, child} -> is_binary(key) and schema?(child, depth + 1) end) and
      is_list(required) and Enum.all?(required, &Map.has_key?(props, &1)) and
      Map.get(s, "additionalProperties", true) in [true, false] and
      (not Map.has_key?(s, "items") or schema?(s["items"], depth + 1)) and
      (not Map.has_key?(s, "enum") or (is_list(s["enum"]) and length(s["enum"]) in 1..64)) and
      Enum.all?(~w(minLength maxLength minItems maxItems), fn k ->
        not Map.has_key?(s, k) or (is_integer(s[k]) and s[k] in 0..8192)
      end) and
      Enum.all?(~w(minimum maximum), fn k -> not Map.has_key?(s, k) or is_number(s[k]) end) and
      (not Map.has_key?(s, "pattern") or pattern?(s["pattern"]))
  end

  def schema?(_, _), do: false

  def valid?(s, value) do
    type?(s["type"], value) and
      (not Map.has_key?(s, "enum") or value in s["enum"]) and fields?(s, value)
  end

  defp type?("object", v), do: is_map(v)
  defp type?("array", v), do: is_list(v)
  defp type?("string", v), do: is_binary(v)
  defp type?("integer", v), do: is_integer(v)
  defp type?("number", v), do: is_number(v)
  defp type?("boolean", v), do: is_boolean(v)
  defp type?("null", v), do: is_nil(v)
  defp type?(_, _), do: false

  defp fields?(s, v) when is_map(v) do
    props = Map.get(s, "properties", %{})

    Enum.all?(Map.get(s, "required", []), &Map.has_key?(v, &1)) and
      Enum.all?(v, fn {k, value} ->
        case props[k] do
          nil -> Map.get(s, "additionalProperties", true)
          child -> valid?(child, value)
        end
      end)
  end

  defp fields?(s, v) when is_binary(v) do
    size = String.length(v)

    size >= Map.get(s, "minLength", 0) and size <= Map.get(s, "maxLength", 8192) and
      (not Map.has_key?(s, "pattern") or Regex.match?(Regex.compile!(s["pattern"]), v))
  end

  defp fields?(s, v) when is_list(v) do
    length(v) >= Map.get(s, "minItems", 0) and length(v) <= Map.get(s, "maxItems", 8192) and
      (not Map.has_key?(s, "items") or Enum.all?(v, &valid?(s["items"], &1)))
  end

  defp fields?(s, v) when is_number(v),
    do: v >= Map.get(s, "minimum", v) and v <= Map.get(s, "maximum", v)

  defp fields?(_, _), do: true

  defp pattern?(v) when is_binary(v) and byte_size(v) <= 256,
    do: match?({:ok, _}, Regex.compile(v))

  defp pattern?(_), do: false
end
