defmodule LakehouseMatrix.Media.Store.S3 do
  @moduledoc "Private S3-compatible blob storage, including Cloudflare R2."
  @behaviour LakehouseMatrix.Media.Store

  def put(id, body, opts \\ []) do
    case request(:put, id, body, opts) do
      {:ok, %{status: status}} when status in 200..299 -> :ok
      _ -> {:error, :storage_unavailable}
    end
  end

  def get(id, opts \\ []) do
    case request(:get, id, "", opts) do
      {:ok, %{status: 200, body: body}} -> {:ok, body}
      {:ok, %{status: 404}} -> {:error, :not_found}
      _ -> {:error, :storage_unavailable}
    end
  end

  def delete(id, opts \\ []) do
    case request(:delete, id, "", opts) do
      {:ok, %{status: status}} when status in 200..299 or status == 404 -> :ok
      _ -> {:error, :storage_unavailable}
    end
  end

  defp request(method, id, body, opts) do
    config = Application.fetch_env!(:lakehouse_matrix, :s3)

    url =
      String.trim_trailing(Keyword.fetch!(config, :endpoint), "/") <>
        "/" <>
        URI.encode(Keyword.fetch!(config, :bucket), &URI.char_unreserved?/1) <>
        "/" <> URI.encode(id, &URI.char_unreserved?/1)

    Req.request(
      [
        method: method,
        url: url,
        body: body,
        decode_body: false,
        redirect: false,
        retry: false,
        receive_timeout: 10_000,
        aws_sigv4: [
          service: :s3,
          region: "auto",
          access_key_id: Keyword.fetch!(config, :access_key_id),
          secret_access_key: Keyword.fetch!(config, :secret_access_key)
        ]
      ] ++ opts
    )
  end
end
