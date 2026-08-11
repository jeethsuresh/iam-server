defmodule LakehouseMatrix.Media.Store.Remote do
  @moduledoc """
  Stub adapter for remote object stores (S3, NFS mounts, etc.).

  Configure `:media_store` to a concrete remote module when ready; this module
  documents the `LakehouseMatrix.Media.Store` contract and returns
  `{:error, :not_implemented}` until replaced.
  """
  @behaviour LakehouseMatrix.Media.Store

  @impl true
  def put(_media_id, _body, _opts \\ []), do: {:error, :not_implemented}

  @impl true
  def get(_media_id, _opts \\ []), do: {:error, :not_implemented}

  @impl true
  def delete(_media_id, _opts \\ []), do: {:error, :not_implemented}
end
