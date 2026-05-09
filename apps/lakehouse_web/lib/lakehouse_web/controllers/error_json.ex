defmodule LakehouseWeb.ErrorJSON do
  @moduledoc false

  def render("error.json", assigns) do
    %{errors: %{detail: Map.get(assigns, :message, "error")}}
  end

  def render("500.json", _assigns) do
    %{errors: %{detail: "internal server error"}}
  end
end
