defmodule LakehouseMatrix.Federation.Transport do
  @moduledoc "HTTPS Matrix server discovery with public-address checks and DNS-pinned connections."
  import Bitwise

  def server_name(name) when is_binary(name) and byte_size(name) in 1..255 do
    uri = URI.parse("https://" <> name)

    valid_host =
      is_binary(uri.host) and
        (Regex.match?(~r/\A[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?\z/, uri.host) or
           match?({:ok, _}, :inet.parse_address(String.to_charlist(uri.host))))

    if valid_host and uri.path in [nil, ""] and is_nil(uri.query) and is_nil(uri.fragment) and
         is_nil(uri.userinfo) and uri.port in 1..65535 do
      explicit = Regex.match?(~r/:\d+\z/, name)

      {:ok,
       %{host: uri.host, port: if(explicit, do: uri.port), explicit: explicit, authority: name}}
    else
      {:error, :invalid_server_name}
    end
  end

  def server_name(_), do: {:error, :invalid_server_name}

  def resolve(server) do
    with {:ok, target} <- server_name(server) do
      if target.explicit or ip_literal?(target.host) do
        {:ok,
         [
           %{
             host: target.host,
             port: target.port || 8448,
             tls_name: target.host,
             authority: target.authority
           }
         ]}
      else
        endpoint = %{host: target.host, port: 443, tls_name: target.host, authority: target.host}

        case fetch(endpoint, "/.well-known/matrix/server") do
          {:ok, %{"m.server" => delegated}} ->
            with {:ok, delegated} <- server_name(delegated),
                 do: {:ok, delegated_endpoints(delegated)}

          _ ->
            {:ok, delegated_endpoints(target)}
        end
      end
    end
  end

  def get_json(server, path) do
    with {:ok, endpoints} <- resolve(server) do
      Enum.reduce_while(endpoints, {:error, :unavailable}, fn endpoint, _ ->
        case fetch(endpoint, path) do
          {:ok, body} -> {:halt, {:ok, body}}
          error -> {:cont, error}
        end
      end)
    end
  end

  def request(method, server, path, content \\ nil) when method in [:get, :post, :put, :delete] do
    case Application.get_env(:lakehouse_matrix, :federation_requester) do
      nil -> request_https(method, server, path, content)
      requester when is_function(requester, 4) -> requester.(method, server, path, content)
    end
  end

  def request_raw(server, path) do
    case Application.get_env(:lakehouse_matrix, :federation_media_requester) do
      nil -> request_https(:get, server, path, nil, true)
      requester when is_function(requester, 2) -> requester.(server, path)
    end
  end

  def get_raw_url(url, opts \\ []) do
    uri = URI.parse(url)

    with true <- uri.scheme == "https" and is_nil(uri.userinfo) and is_nil(uri.fragment),
         true <- is_binary(uri.host) and uri.port in 1..65535 do
      authority = if String.contains?(uri.host, ":"), do: "[" <> uri.host <> "]", else: uri.host
      authority = authority <> if(uri.port == 443, do: "", else: ":" <> to_string(uri.port))
      path = (uri.path || "/") <> if(uri.query, do: "?" <> uri.query, else: "")

      fetch(%{host: uri.host, port: uri.port, tls_name: uri.host, authority: authority}, path,
        raw: true,
        max_bytes: Keyword.get(opts, :max_bytes, 10_551_296)
      )
    else
      _ -> {:error, :blocked_address}
    end
  rescue
    _ -> {:error, :invalid_param}
  end

  defp request_https(method, server, path, content, raw \\ false) do
    with {:ok, authorization} <-
           LakehouseMatrix.Federation.Signing.authorization(
             method |> to_string() |> String.upcase(),
             path,
             server,
             content
           ),
         {:ok, endpoints} <- resolve(server) do
      options = [
        method: method,
        content: content,
        headers: [{"authorization", authorization}, {"content-type", "application/json"}],
        raw: raw,
        max_bytes: if(raw, do: 10_551_296, else: 33_554_432)
      ]

      Enum.reduce_while(endpoints, {:error, :unavailable}, fn endpoint, _ ->
        case fetch(endpoint, path, options) do
          {:ok, body} -> {:halt, {:ok, body}}
          {:error, {:http, status, _}} = error when status < 500 -> {:halt, error}
          error -> {:cont, error}
        end
      end)
    end
  end

  def fetch(endpoint, path, request_options \\ []) do
    with {:ok, ips} <- addresses(endpoint.host), true <- String.starts_with?(path, "/") do
      Enum.reduce_while(ips, {:error, :unavailable}, fn ip, _ ->
        address = ip |> :inet.ntoa() |> to_string()
        address = if tuple_size(ip) == 8, do: "[" <> address <> "]", else: address
        url = "https://#{address}:#{endpoint.port}#{path}"

        options = [
          url: url,
          method: Keyword.get(request_options, :method, :get),
          headers:
            [{"host", endpoint.authority}, {"accept-encoding", "identity"}] ++
              Keyword.get(request_options, :headers, []),
          redirect: false,
          retry: false,
          compressed: false,
          decode_body: false,
          receive_timeout: 5_000,
          connect_options: [
            timeout: 5_000,
            hostname: endpoint.tls_name,
            transport_opts: [verify: :verify_peer, cacerts: :public_key.cacerts_get()]
          ],
          into: fn {:data, data}, {req, resp} ->
            body = (resp.private[:matrix_body] || "") <> data

            if byte_size(body) > Keyword.get(request_options, :max_bytes, 1_048_576),
              do: raise(ArgumentError, "Matrix discovery response exceeds limit")

            {:cont, {req, %{resp | private: Map.put(resp.private, :matrix_body, body)}}}
          end
        ]

        options =
          if request_options[:content],
            do: Keyword.put(options, :body, Jason.encode!(request_options[:content])),
            else: options

        case Req.request(options) do
          {:ok, %{status: 200, private: private, headers: headers}} ->
            if request_options[:raw] do
              {:halt, {:ok, %{body: private[:matrix_body] || "", headers: headers}}}
            else
              case Jason.decode(private[:matrix_body] || "") do
                {:ok, body} when is_map(body) -> {:halt, {:ok, body}}
                _ -> {:cont, {:error, :invalid_json}}
              end
            end

          {:ok, %{status: status, private: private}} ->
            body =
              case Jason.decode(private[:matrix_body] || "") do
                {:ok, value} -> value
                _ -> %{}
              end

            {:cont, {:error, {:http, status, body}}}

          _ ->
            {:cont, {:error, :unavailable}}
        end
      end)
    else
      _ -> {:error, :blocked_address}
    end
  rescue
    _ -> {:error, :unavailable}
  end

  def addresses(host) do
    ips =
      case :inet.parse_address(String.to_charlist(host)) do
        {:ok, ip} ->
          [ip]

        _ ->
          for family <- [:inet, :inet6],
              {:ok, addresses} <- [:inet.getaddrs(String.to_charlist(host), family)],
              ip <- addresses,
              do: ip
      end

    if ips != [] and Enum.all?(ips, &public_ip?/1),
      do: {:ok, Enum.uniq(ips)},
      else: {:error, :blocked_address}
  end

  def public_ip?({a, b, c, _}) do
    a not in [0, 10, 127] and a < 224 and not (a == 100 and b in 64..127) and
      not (a == 169 and b == 254) and not (a == 172 and b in 16..31) and
      not (a == 192 and (b == 168 or (b == 0 and c in [0, 2]))) and
      not (a == 198 and (b in [18, 19] or (b == 51 and c == 100))) and
      not (a == 203 and b == 0 and c == 113)
  end

  def public_ip?({0, 0, 0, 0, 0, 0xFFFF, hi, lo}),
    do: public_ip?({hi >>> 8, hi &&& 255, lo >>> 8, lo &&& 255})

  def public_ip?({a, b, _, _, _, _, _, _}),
    do: (a &&& 0xE000) == 0x2000 and not (a == 0x2001 and b in [0, 2, 0xDB8]) and a != 0x2002

  def public_ip?(_), do: false

  defp delegated_endpoints(%{explicit: true} = t),
    do: [%{host: t.host, port: t.port, tls_name: t.host, authority: t.authority}]

  defp delegated_endpoints(t) do
    records = :inet_res.lookup(String.to_charlist("_matrix-fed._tcp." <> t.host), :in, :srv)

    records =
      if records == [],
        do: :inet_res.lookup(String.to_charlist("_matrix._tcp." <> t.host), :in, :srv),
        else: records

    if records == [] do
      [%{host: t.host, port: 8448, tls_name: t.host, authority: t.authority}]
    else
      records
      |> Enum.sort_by(fn {priority, weight, _, _} -> {priority, -weight} end)
      |> Enum.take(10)
      |> Enum.map(fn {_, _, port, host} ->
        %{
          host: host |> to_string() |> String.trim_trailing("."),
          port: port,
          tls_name: t.host,
          authority: t.authority
        }
      end)
    end
  end

  defp ip_literal?(host), do: match?({:ok, _}, :inet.parse_address(String.to_charlist(host)))
end
