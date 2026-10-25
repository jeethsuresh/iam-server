defmodule LakehouseMatrix.Federation.Media do
  @moduledoc "Bounded Matrix multipart media, fetched with authenticated, DNS-pinned federation requests."
  alias LakehouseMatrix.Federation.Transport
  @limit 10 * 1024 * 1024
  @inline ~w(text/css text/plain text/csv application/json application/ld+json image/jpeg image/gif image/png image/apng image/webp image/avif video/mp4 video/webm video/ogg video/quicktime audio/mp4 audio/webm audio/aac audio/mpeg audio/ogg audio/wave audio/wav audio/x-wav audio/x-pn-wav audio/flac audio/x-flac)

  def valid_id?(id),
    do: is_binary(id) and byte_size(id) in 1..255 and Regex.match?(~r/\A[A-Za-z0-9_-]+\z/, id)

  def download(server, id, thumbnail \\ nil) do
    with {:ok, _} <- Transport.server_name(server), true <- valid_id?(id) do
      action = if thumbnail, do: "thumbnail", else: "download"
      query = if thumbnail, do: "?" <> URI.encode_query(thumbnail), else: ""

      with {:ok, response} <-
             Transport.request_raw(
               server,
               "/_matrix/federation/v1/media/" <> action <> "/" <> id <> query
             ),
           {:ok, media} <- decode(response) do
        if location = media[:location] do
          with {:ok, raw} <- Transport.get_raw_url(location),
               true <- byte_size(raw.body) <= @limit do
            {:ok,
             %{
               body: raw.body,
               content_type: safe_type(header(raw.headers, "content-type")),
               filename: filename(header(raw.headers, "content-disposition"))
             }}
          else
            _ -> {:error, :unavailable}
          end
        else
          {:ok, media}
        end
      end
    else
      _ -> {:error, :invalid_param}
    end
  end

  def encode(%{body: body, content_type: type, filename: filename}) do
    boundary = "matrix-" <> Base.url_encode64(:crypto.strong_rand_bytes(24), padding: false)

    wire =
      "--" <>
        boundary <>
        "\r\nContent-Type: application/json\r\n\r\n{}\r\n--" <>
        boundary <>
        "\r\nContent-Type: " <>
        safe_type(type) <>
        "\r\nContent-Disposition: " <>
        disposition(type, filename) <>
        "\r\n\r\n" <>
        body <> "\r\n--" <> boundary <> "--\r\n"

    {"multipart/mixed; boundary=" <> boundary, wire}
  end

  def decode(%{body: body, headers: headers}) when byte_size(body) <= @limit + 65_536 do
    with type when is_binary(type) <- header(headers, "content-type"),
         {:ok, "multipart", "mixed", params} <- Plug.Conn.Utils.media_type(type),
         boundary when is_binary(boundary) <- params["boundary"],
         true <-
           byte_size(boundary) in 1..70 and
             Regex.match?(~r/\A[0-9A-Za-z'()+_,.\/:=? -]+\z/, boundary),
         [first, second, ending] <- :binary.split(body, "--" <> boundary, [:global]) |> tl(),
         true <- String.starts_with?(ending, "--"),
         {:ok, first_headers, metadata} <- part(first),
         true <-
           String.starts_with?(header(first_headers, "content-type") || "", "application/json"),
         true <- byte_size(metadata) <= 65_536,
         {:ok, metadata} <- Jason.decode(metadata),
         true <- is_map(metadata),
         {:ok, media_headers, bytes} <- part(second) do
      case header(media_headers, "location") do
        nil ->
          if byte_size(bytes) <= @limit,
            do:
              {:ok,
               %{
                 body: bytes,
                 content_type: safe_type(header(media_headers, "content-type")),
                 filename: filename(header(media_headers, "content-disposition"))
               }},
            else: {:error, :too_large}

        location ->
          if byte_size(location) <= 8192,
            do: {:ok, %{location: location}},
            else: {:error, :invalid_media}
      end
    else
      _ -> {:error, :invalid_media}
    end
  rescue
    _ -> {:error, :invalid_media}
  end

  def decode(_), do: {:error, :invalid_media}

  def disposition(type, filename) do
    base = if safe_type(type) in @inline, do: "inline", else: "attachment"

    if is_binary(filename) and String.valid?(filename) and filename != "" do
      clean = filename |> String.replace(~r/[\x00-\x1f\x7f]/u, "") |> String.slice(0, 255)
      ascii = clean |> String.replace(~r/[^\x20-\x7e]/u, "_") |> String.replace(["\\", "\""], "_")

      base <>
        "; filename=\"" <>
        ascii <> "\"; filename*=UTF-8''" <> URI.encode(clean, &URI.char_unreserved?/1)
    else
      base
    end
  end

  def safe_type(type) when is_binary(type) do
    case Plug.Conn.Utils.media_type(type) do
      {:ok, major, minor, _} -> major <> "/" <> minor
      _ -> "application/octet-stream"
    end
  end

  def safe_type(_), do: "application/octet-stream"

  defp part("\r\n" <> bytes) do
    with [headers, body] <- :binary.split(bytes, "\r\n\r\n"),
         true <- byte_size(headers) <= 16_384 and String.ends_with?(body, "\r\n"),
         entries <- :binary.split(headers, "\r\n", [:global]),
         true <- length(entries) <= 50 do
      parsed =
        Enum.reduce_while(entries, %{}, fn line, acc ->
          case :binary.split(line, ":") do
            [key, value] ->
              key = String.downcase(key)

              if Regex.match?(~r/\A[a-z0-9-]+\z/, key) and not Map.has_key?(acc, key),
                do: {:cont, Map.put(acc, key, String.trim(value))},
                else: {:halt, :invalid}

            _ ->
              {:halt, :invalid}
          end
        end)

      if is_map(parsed),
        do: {:ok, parsed, binary_part(body, 0, byte_size(body) - 2)},
        else: {:error, :invalid_media}
    else
      _ -> {:error, :invalid_media}
    end
  end

  defp part(_), do: {:error, :invalid_media}

  defp header(headers, name) when is_map(headers) do
    case Map.get(headers, name) do
      [value | _] -> value
      value -> value
    end
  end

  defp header(headers, name) when is_list(headers),
    do:
      Enum.find_value(headers, fn {key, value} -> if String.downcase(key) == name, do: value end)

  defp header(_, _), do: nil

  defp filename(value) when is_binary(value) do
    params = value |> String.split(";", parts: 2) |> Enum.at(1, "") |> Plug.Conn.Utils.params()

    case params["filename*"] do
      "UTF-8''" <> encoded -> URI.decode(encoded)
      "utf-8''" <> encoded -> URI.decode(encoded)
      _ -> params["filename"]
    end
  rescue
    _ -> nil
  end

  defp filename(_), do: nil
end
