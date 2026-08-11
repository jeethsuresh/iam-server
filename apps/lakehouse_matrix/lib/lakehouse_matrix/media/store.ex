defmodule LakehouseMatrix.Media.Store do
  @moduledoc """
  Behaviour for media blob storage (local disk, S3, NFS, …).
  """

  @type media_id :: String.t()
  @type opts :: keyword()

  @callback put(media_id, binary(), opts) :: :ok | {:error, term()}
  @callback get(media_id, opts) :: {:ok, binary()} | {:error, term()}
  @callback delete(media_id, opts) :: :ok | {:error, term()}
end
