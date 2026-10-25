defmodule LakehouseMatrix.UrlPreviews do
  @moduledoc "Explicit, authenticated URL summaries over bounded, public-address HTTPS requests."
  import Ecto.Query
  alias LakehouseIam.Repo
  alias LakehouseMatrix.{ClientStore, ClientSync}
  alias LakehouseMatrix.Federation.Transport
  @limit 1_048_576

  def preview(principal, params, fetcher \\ &fetch/1) do
    with {:ok, url} <- url(params["url"]),
         {:ok, _} <- ClientSync.integer(params["ts"], 0, 0, 9_007_199_254_740_991),
         {:ok, cached} <- reserve(principal, url) do
      if cached do
        {:ok, cached}
      else
        with {:ok, response, headers} <- fetch_summary(url, fetcher) do
          ttl = ttl(headers)

          if ttl > 0 do
            Repo.insert_all(
              "matrix_url_previews",
              [
                %{
                  url_hash: ClientStore.hash(url),
                  response: response,
                  expires_at: DateTime.add(ClientStore.now(), ttl, :second)
                }
              ],
              on_conflict: {:replace, [:response, :expires_at]},
              conflict_target: [:url_hash]
            )
          end

          {:ok, response}
        else
          {:error, :blocked_address} -> {:error, :forbidden}
          {:error, :rate_limited} -> {:error, :rate_limited}
          _ -> {:error, :unavailable}
        end
      end
    else
      {:error, _} = error -> error
      _ -> {:error, :invalid_param}
    end
  end

  defp fetch(url) do
    case Application.get_env(:lakehouse_matrix, :url_preview_requester) do
      nil -> Transport.get_raw_url(url, max_bytes: @limit)
      fetcher when is_function(fetcher, 1) -> fetcher.(url)
    end
  end

  defp fetch_summary(url, fetcher) do
    parent = self()
    ref = make_ref()

    if Process.whereis(LakehouseMatrix.PreviewTasks) do
      case Task.Supervisor.start_child(LakehouseMatrix.PreviewTasks, fn ->
             {:ok, timer} = :timer.exit_after(10_000, :kill)

             result =
               try do
                 with {:ok, %{body: body, headers: headers}} <- fetcher.(url),
                      true <- is_binary(body) and byte_size(body) <= @limit and is_map(headers),
                      {:ok, response} <- summary(url, body, headers),
                      do: {:ok, response, headers},
                      else: (error -> error)
               rescue
                 _ -> {:error, :unavailable}
               after
                 :timer.cancel(timer)
               end

             send(parent, {ref, result})
           end) do
        {:ok, pid} ->
          monitor = Process.monitor(pid)

          receive do
            {^ref, result} ->
              Process.demonitor(monitor, [:flush])
              result

            {:DOWN, ^monitor, _, _, _} ->
              {:error, :unavailable}
          after
            11_000 ->
              Process.exit(pid, :kill)
              Process.demonitor(monitor, [:flush])
              {:error, :unavailable}
          end

        {:error, :max_children} ->
          {:error, :rate_limited}

        _ ->
          {:error, :unavailable}
      end
    else
      {:error, :unavailable}
    end
  end

  defp url(value) when is_binary(value) and byte_size(value) in 1..8192 do
    with true <- String.valid?(value),
         %URI{scheme: scheme, host: host, userinfo: nil, port: port} = uri <- URI.parse(value),
         true <- is_binary(scheme) and String.downcase(scheme) == "https",
         true <- is_binary(host) and port in 1..65535,
         authority = if(String.contains?(host, ":"), do: "[" <> host <> "]", else: host),
         {:ok, _} <- Transport.server_name(authority <> ":" <> to_string(port)) do
      case :inet.parse_address(String.to_charlist(host)) do
        {:ok, ip} ->
          if Transport.public_ip?(ip),
            do:
              {:ok,
               URI.to_string(%{
                 uri
                 | scheme: "https",
                   host: String.downcase(host),
                   path: uri.path || "/",
                   fragment: nil
               })},
            else: {:error, :forbidden}

        _ ->
          {:ok,
           URI.to_string(%{
             uri
             | scheme: "https",
               host: String.downcase(host),
               path: uri.path || "/",
               fragment: nil
           })}
      end
    else
      _ -> {:error, :invalid_param}
    end
  rescue
    _ -> {:error, :invalid_param}
  end

  defp url(_), do: {:error, :invalid_param}

  defp reserve(principal, url) do
    Repo.transaction(fn ->
      ClientStore.lock!()
      now = ClientStore.now()
      since = DateTime.add(now, -60, :second)
      Repo.delete_all(from r in "matrix_preview_requests", where: r.requested_at < ^since)
      Repo.delete_all(from c in "matrix_url_previews", where: c.expires_at <= ^now)

      count =
        Repo.aggregate(
          from(r in "matrix_preview_requests",
            where: r.principal_id == type(^principal, :binary_id)
          ),
          :count
        )

      if count >= 30, do: Repo.rollback(:rate_limited)

      Repo.insert_all("matrix_preview_requests", [
        %{principal_id: ClientStore.dump_id(principal), requested_at: now}
      ])

      Repo.one(
        from c in "matrix_url_previews",
          where: c.url_hash == ^ClientStore.hash(url),
          select: c.response
      )
    end)
  end

  defp summary(url, body, headers) do
    type =
      headers
      |> header("content-type")
      |> to_string()
      |> String.split(";")
      |> hd()
      |> String.trim()
      |> String.downcase()

    if type in ["text/html", "application/xhtml+xml"] and String.valid?(body) do
      with {:ok, document} <- Floki.parse_document(body) do
        response =
          %{
            "og:url" => url,
            "og:title" => meta(document, "og:title") || text(document, "title"),
            "og:description" => meta(document, "og:description") || meta(document, "description"),
            "og:site_name" => meta(document, "og:site_name")
          }
          |> Map.reject(fn {_, value} -> is_nil(value) or value == "" end)

        {:ok, response}
      else
        _ -> {:error, :unavailable}
      end
    else
      # Matrix permits an empty OpenGraph result. Do not expose arbitrary
      # response bodies, active content, remote image URLs or inline data URIs.
      {:ok, %{}}
    end
  end

  defp meta(document, key) do
    Floki.find(document, "meta")
    |> Enum.find_value(fn {_, attrs, _} ->
      attrs = Map.new(attrs)

      if String.downcase(attrs["property"] || attrs["name"] || "") == key,
        do: clean(attrs["content"])
    end)
  end

  defp text(document, selector), do: document |> Floki.find(selector) |> Floki.text() |> clean()

  defp clean(value) when is_binary(value),
    do:
      value |> String.replace(~r/[\x00-\x1f\x7f]/u, " ") |> String.trim() |> String.slice(0, 2048)

  defp clean(_), do: nil

  defp ttl(headers) do
    cache = headers |> header("cache-control") |> to_string() |> String.downcase()

    cond do
      String.contains?(cache, ["no-store", "no-cache", "private"]) or
          Enum.any?(
            String.split(to_string(header(headers, "vary")), ","),
            &(String.trim(&1) == "*")
          ) ->
        0

      true ->
        case Regex.run(~r/(?:^|[,\s])max-age=(\d+)/, cache) do
          [_, seconds] when byte_size(seconds) <= 9 -> min(String.to_integer(seconds), 300)
          [_, _] -> 0
          _ -> 300
        end
    end
  end

  defp header(headers, name) do
    case headers[name] do
      values when is_list(values) -> Enum.join(values, ",")
      value -> value
    end
  end
end
