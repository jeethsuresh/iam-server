defmodule LakehouseWeb.Layouts do
  @moduledoc false
  use Phoenix.Component

  use Phoenix.VerifiedRoutes,
    endpoint: LakehouseWeb.Endpoint,
    router: LakehouseWeb.Router,
    statics: LakehouseWeb.StaticPaths.paths()

  embed_templates "layouts/*"
end
