defmodule LakehouseWeb do
  @moduledoc false

  def static_paths, do: LakehouseWeb.StaticPaths.paths()

  def router do
    quote do
      use Phoenix.Router

      import Plug.Conn
      import Phoenix.Controller
    end
  end

  def channel do
    quote do
      use Phoenix.Channel
    end
  end

  def controller do
    quote do
      use Phoenix.Controller,
        formats: [:html, :json],
        layouts: [html: LakehouseWeb.Layouts]

      import Plug.Conn

      unquote(verified_routes())
    end
  end

  def html do
    quote do
      use Phoenix.Component

      import Phoenix.Controller,
        only: [get_csrf_token: 0, view_module: 1, view_template: 1]

      import Phoenix.HTML

      unquote(html_helpers())
    end
  end

  defp html_helpers do
    quote do
      unquote(verified_routes())
    end
  end

  defp verified_routes do
    quote do
      use Phoenix.VerifiedRoutes,
        endpoint: LakehouseWeb.Endpoint,
        router: LakehouseWeb.Router,
        statics: LakehouseWeb.static_paths()
    end
  end

  defmacro __using__(which) when is_atom(which) do
    apply(__MODULE__, which, [])
  end
end
