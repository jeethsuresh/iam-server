defmodule LakehouseWeb.Endpoint do
  use Phoenix.Endpoint, otp_app: :lakehouse_web

  @session_options Application.compile_env(:lakehouse_web, :session_options,
                     store: :cookie,
                     key: "_lakehouse_web_key",
                     signing_salt: "lakehouse sess sign",
                     same_site: "Lax"
                   )

  socket "/socket", LakehouseWeb.UserSocket,
    websocket: true,
    longpoll: false

  socket "/live", Phoenix.LiveView.Socket, websocket: [connect_info: [session: @session_options]]

  plug Plug.Static,
    at: "/",
    from: :lakehouse_web,
    gzip: false,
    only: LakehouseWeb.static_paths()

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
  plug LakehouseWeb.Plugs.AppCors
  plug LakehouseWeb.Router
end
