defmodule LakehouseWeb.Layouts do
  @moduledoc false
  use Phoenix.Component

  import Phoenix.Controller, only: [get_csrf_token: 0]

  use Phoenix.VerifiedRoutes,
    endpoint: LakehouseWeb.Endpoint,
    router: LakehouseWeb.Router,
    statics: LakehouseWeb.StaticPaths.paths()

  embed_templates "layouts/*"
end
