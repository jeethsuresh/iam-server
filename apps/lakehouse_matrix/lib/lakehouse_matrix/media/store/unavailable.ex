defmodule LakehouseMatrix.Media.Store.Unavailable do
  @moduledoc "Fail closed rather than write uploads to an ephemeral container disk."
  @behaviour LakehouseMatrix.Media.Store
  def put(_, _, _ \\ []), do: {:error, :storage_unavailable}
  def get(_, _ \\ []), do: {:error, :storage_unavailable}
  def delete(_, _ \\ []), do: {:error, :storage_unavailable}
end
