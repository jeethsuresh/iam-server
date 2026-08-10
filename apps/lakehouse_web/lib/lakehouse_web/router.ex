defmodule LakehouseWeb.Router do
  use LakehouseWeb, :router

  import Phoenix.LiveView.Router

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_live_flash
    plug :put_root_layout, html: {LakehouseWeb.Layouts, :root}
    plug :protect_from_forgery
    plug :put_secure_browser_headers
  end

  pipeline :browser_session do
    plug :accepts, ["html", "json"]
    plug :fetch_session
    plug :fetch_live_flash
  end

  pipeline :api do
    plug :accepts, ["json"]
  end

  pipeline :authenticated do
    plug LakehouseWeb.Plugs.BearerAuth
  end

  pipeline :session_authenticated do
    plug LakehouseWeb.Plugs.SessionOrBearerAuth
  end

  pipeline :require_admin do
    plug LakehouseWeb.Plugs.RequireAdmin
  end

  scope "/", LakehouseWeb do
    pipe_through :browser

    get "/", PageController, :home
    get "/register", PageController, :register
    post "/web/login", WebAuthController, :login
    post "/web/register", WebAuthController, :register
  end

  scope "/", LakehouseWeb do
    pipe_through :browser_session

    get "/logout", IamSessionController, :delete
  end

  scope "/", LakehouseWeb do
    pipe_through [:browser, :session_authenticated]

    live_session :require_user,
      on_mount: [{LakehouseWeb.UserAuth, :require_user}],
      root_layout: {LakehouseWeb.Layouts, :root} do
      live "/rooms", RoomLive, :index
      live "/rooms/:id", RoomLive, :show
    end

    get "/settings", SettingsController, :index
    get "/profile", IamProfileController, :show

    post "/web/settings/password", ProfilePasswordController, :update_browser
    post "/web/admin/approve", AdminController, :approve

    get "/profile/password", SettingsController, :redirect_legacy
    get "/admin", SettingsController, :redirect_legacy
  end

  # --- iam-server compatible JSON API (no CSRF) ---
  scope "/", LakehouseWeb do
    pipe_through :api

    post "/backend/register", IamBackendController, :create
    post "/login", IamSessionController, :create
    post "/register", IamRegistrationController, :create
  end

  scope "/", LakehouseWeb do
    pipe_through [:api, :authenticated]

    post "/profile/password", ProfilePasswordController, :update_api
  end

  scope "/", LakehouseWeb do
    pipe_through [:api, :authenticated, :require_admin]

    post "/admin/approve", AdminController, :approve_api
  end

  scope "/api/v1", LakehouseWeb.Api, as: :api do
    pipe_through [:api, :authenticated]

    resources "/rooms", RoomController, only: [:index, :create, :show]
  end

  scope "/_matrix/client", LakehouseWeb.Matrix, as: :matrix do
    pipe_through :api

    get "/versions", ClientController, :versions
    post "/v3/login", ClientController, :login
  end

  scope "/_matrix/client", LakehouseWeb.Matrix, as: :matrix do
    pipe_through [:api, LakehouseWeb.Plugs.MatrixAuth]

    get "/v3/sync", ClientController, :sync
    post "/v3/createRoom", ClientController, :create_room
    post "/v3/join/:roomIdOrAlias", ClientController, :join_room
    post "/v3/rooms/:roomId/invite", ClientController, :invite
    post "/v3/rooms/:roomId/leave", ClientController, :leave_room
    post "/v3/rooms/:roomId/kick", ClientController, :kick
    put "/v3/rooms/:roomId/send/:eventType/:txnId", ClientController, :send_event
    put "/v3/rooms/:roomId/state/:eventType", ClientController, :put_state
    put "/v3/rooms/:roomId/state/:eventType/", ClientController, :put_state
    get "/v3/rooms/:roomId/messages", ClientController, :messages
  end

  scope "/_matrix/media", LakehouseWeb.Matrix, as: :matrix_media do
    pipe_through [:api, LakehouseWeb.Plugs.MatrixAuth]

    post "/v3/upload", MediaController, :upload
    get "/v3/download/:serverName/:mediaId", MediaController, :download
  end
end
