defmodule LakehouseWeb.Endpoint do
  use Phoenix.Endpoint, otp_app: :lakehouse_web

  @session_options Application.compile_env(:lakehouse_web, :session_options, [
                     store: :cookie,
                     key: "_lakehouse_web_key",
                     signing_salt: "lakehouse sess sign",
                     same_site: "Lax"
                   ])

  socket "/socket", LakehouseWeb.UserSocket,
    websocket: true,
    longpoll: false

  plug Plug.RequestId

  plug Plug.Telemetry,
    event_prefix: [:phoenix, :endpoint]

  plug Plug.Session, @session_options

  plug Plug.Parsers,
    parsers: [:urlencoded, :multipart, :json],
    pass: ["*/*"],
    json_decoder: Jason

  plug Plug.MethodOverride
  plug Plug.Head
  plug LakehouseWeb.Router
end
