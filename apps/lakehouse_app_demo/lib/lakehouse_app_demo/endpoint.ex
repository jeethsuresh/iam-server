defmodule LakehouseAppDemo.Endpoint do
  use Phoenix.Endpoint, otp_app: :lakehouse_app_demo

  plug Plug.RequestId
  plug Plug.Telemetry, event_prefix: [:phoenix, :endpoint]

  plug Plug.Parsers,
    parsers: [:urlencoded, :multipart, :json],
    pass: ["*/*"],
    json_decoder: Jason

  plug Plug.MethodOverride
  plug Plug.Head
  plug Plug.Session, store: :cookie, key: "_lakehouse_app_demo_key", signing_salt: "demo_salt"

  plug LakehouseAppDemo.Router
end
