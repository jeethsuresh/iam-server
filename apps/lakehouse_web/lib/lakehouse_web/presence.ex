defmodule LakehouseWeb.Presence do
  @moduledoc false
  use Phoenix.Presence,
    otp_app: :lakehouse_web,
    pubsub_server: LakehouseWeb.PubSub
end
