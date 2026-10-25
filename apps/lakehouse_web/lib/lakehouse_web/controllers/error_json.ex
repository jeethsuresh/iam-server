defmodule LakehouseWeb.ErrorJSON do
  @moduledoc false

  def render(template, %{conn: %Plug.Conn{request_path: "/_matrix/" <> _}}) do
    case template do
      "400.json" ->
        %{"errcode" => "M_NOT_JSON", "error" => "The request body is not valid JSON"}

      "404.json" ->
        %{"errcode" => "M_UNRECOGNIZED", "error" => "Unrecognized Matrix endpoint"}

      "413.json" ->
        %{"errcode" => "M_TOO_LARGE", "error" => "The request exceeds the server limit"}

      _ ->
        %{"errcode" => "M_UNKNOWN", "error" => "The Matrix request failed"}
    end
  end

  def render("error.json", assigns) do
    %{errors: %{detail: Map.get(assigns, :message, "error")}}
  end

  def render("500.json", _assigns) do
    %{errors: %{detail: "internal server error"}}
  end
end
