defmodule LakehouseIam.Auth.CallbackURL do
  @moduledoc """
  Validates `tokenURL` / `redirectURL` like iam-server `ValidateCallbackURL`:
  absolute http(s); blocks metadata range `169.254.0.0/16` always; optionally blocks
  loopback/private/link-local unless `IAM_RELAXED_CALLBACK_URLS` is set.
  """

  @metadata_msg "must not target metadata range 169.254.0.0/16"

  @spec validate(String.t(), String.t()) :: :ok | {:error, String.t()}
  def validate(raw, name) when is_binary(raw) and is_binary(name) do
    relaxed = Application.fetch_env!(:lakehouse_iam, :relaxed_callback_urls)

    case URI.parse(raw) do
      %URI{scheme: scheme, host: host}
      when scheme in ["http", "https"] and is_binary(host) and host != "" ->
        host_for_parse =
          case String.contains?(host, ":") and not String.starts_with?(host, "[") do
            true -> "[#{host}]"
            false -> host
          end

        case :inet.parse_address(String.to_charlist(host_for_parse)) do
          {:ok, ip} ->
            validate_ip(ip, relaxed, name)

          {:error, _} ->
            validate_hostname(host, relaxed, name)
        end

      _ ->
        {:error, "#{name} must be an absolute URL"}
    end
  end

  defp validate_hostname(host, relaxed, name) do
    case :inet_res.lookup(String.to_charlist(host), :in, :a) ++
           :inet_res.lookup(String.to_charlist(host), :in, :aaaa) do
      [] ->
        {:error, "#{name}: could not resolve host"}

      ips ->
        Enum.reduce_while(ips, :ok, fn ip, _ ->
          case validate_ip(ip, relaxed, name) do
            :ok -> {:cont, :ok}
            {:error, _} = err -> {:halt, err}
          end
        end)
    end
  end

  defp validate_ip(ip, relaxed, name) do
    cond do
      metadata_169?(ip) ->
        {:error, "#{name} #{@metadata_msg}"}

      relaxed ->
        :ok

      ipv4?(ip) and loopback_or_private_ipv4?(ip) ->
        {:error,
         "#{name} must not target loopback, private, or link-local addresses (set IAM_RELAXED_CALLBACK_URLS=1 for local dev)"}

      ipv6?(ip) and loopback_or_private_ipv6?(ip) ->
        {:error,
         "#{name} must not target loopback, private, or link-local addresses (set IAM_RELAXED_CALLBACK_URLS=1 for local dev)"}

      true ->
        :ok
    end
  end

  defp ipv4?(ip), do: tuple_size(ip) == 4
  defp ipv6?(ip), do: tuple_size(ip) == 8

  defp metadata_169?(ip) when tuple_size(ip) == 4 do
    elem(ip, 0) == 169 and elem(ip, 1) == 254
  end

  defp metadata_169?(_), do: false

  defp loopback_or_private_ipv4?(ip) when tuple_size(ip) == 4 do
    a = elem(ip, 0)

    a == 127 or a == 10 or a == 0 or
      (a == 172 and elem(ip, 1) >= 16 and elem(ip, 1) <= 31) or
      (a == 192 and elem(ip, 1) == 168) or
      (a == 169 and elem(ip, 1) == 254)
  end

  defp loopback_or_private_ipv4?(_), do: false

  # IPv6 loopback ::1 and link-local fe80::/10 (simplified check on high segment).
  defp loopback_or_private_ipv6?(ip) when tuple_size(ip) == 8 do
    case ip do
      {0, 0, 0, 0, 0, 0, 0, 1} -> true
      {0xfe80, _, _, _, _, _, _, _} -> true
      {0xFEC0, _, _, _, _, _, _, _} -> true
      _ -> false
    end
  end

  defp loopback_or_private_ipv6?(_), do: false
end
