defmodule LakehouseMatrix.Events.Handler do
  @moduledoc """
  Behaviour for Matrix event type handlers.
  """

  alias LakehouseMatrix.Events.Context

  @callback handle(Context.t()) :: {:ok, map()} | {:error, term()}
end
