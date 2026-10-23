defmodule LakehouseWeb.Router do
  use LakehouseWeb, :router

  import Phoenix.LiveView.Router

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_live_flash
    plug LakehouseWeb.Plugs.RenewBrowserSession
    plug :put_root_layout, html: {LakehouseWeb.Layouts, :root}
    plug :protect_from_forgery
    plug :put_secure_browser_headers
  end

  pipeline :browser_session do
    plug :accepts, ["html", "json"]
    plug :fetch_session
    plug :fetch_live_flash
    plug LakehouseWeb.Plugs.RenewBrowserSession
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
    post "/web/logout", IamSessionController, :delete
    get "/logout", IamSessionController, :confirm_logout
  end

  scope "/web", LakehouseWeb do
    pipe_through [:browser_session, :session_authenticated]
    get "/session", IamSessionController, :show
  end

  scope "/", LakehouseWeb do
    pipe_through :browser

    get "/oauth/start", OAuthController, :start
    get "/oauth/authorize", OAuthController, :authorize
  end

  scope "/", LakehouseWeb do
    pipe_through [:browser, :session_authenticated]

    live_session :require_user,
      on_mount: [{LakehouseWeb.UserAuth, :require_user}],
      root_layout: {LakehouseWeb.Layouts, :root} do
      live "/groups", RoomLive, :index
      live "/groups/:id", RoomLive, :show
      live "/rooms", RoomLive, :index
      live "/rooms/:id", RoomLive, :show
    end

    get "/dashboard", DashboardController, :index
    get "/services/manage", DashboardController, :catalog
    post "/services", DashboardController, :create
    post "/services/:id/delete", DashboardController, :delete
    get "/services/:id/launch", DashboardController, :launch

    get "/settings", SettingsController, :index
    get "/profile", IamProfileController, :show
    get "/media/:serverName/:mediaId", WebMediaController, :show

    post "/web/settings/password", ProfilePasswordController, :update_browser
    post "/web/admin/approve", AdminController, :approve
    post "/web/settings/apps/revoke", SettingsController, :revoke_app

    get "/oauth/consent", OAuthController, :consent_form
    post "/oauth/consent", OAuthController, :consent_submit

    get "/profile/password", SettingsController, :redirect_legacy
    get "/admin", SettingsController, :redirect_legacy
  end

  # --- iam-server compatible JSON API (no CSRF) ---
  scope "/", LakehouseWeb do
    pipe_through :api

    get "/healthz", DiscoveryController, :health
    get "/readyz", DiscoveryController, :ready
    get "/.well-known/webfinger", DiscoveryController, :webfinger
    get "/.well-known/iam-configuration", DiscoveryController, :configuration
    get "/.well-known/matrix/client", DiscoveryController, :matrix_client

    post "/backend/register", IamBackendController, :create
    post "/login", IamSessionController, :create
    post "/refresh", IamSessionController, :refresh
    post "/revoke", IamSessionController, :revoke
    post "/register", IamRegistrationController, :create
    post "/oauth/token", OAuthController, :token
    get "/oauth/session", OAuthController, :session_check
    post "/oauth/broker/authorize", NativeBrokerController, :authorize
  end

  scope "/app/v1", LakehouseWeb.App, as: :app_v1 do
    pipe_through [:api, LakehouseWeb.Plugs.AppTokenAuth]

    get "/groups", GroupController, :index
    post "/groups", GroupController, :create
    post "/direct", GroupController, :direct
    post "/groups/:id/membership", GroupController, :membership
    patch "/groups/:id", GroupController, :update
    get "/groups/:id/channels", GroupController, :channels
    post "/groups/:id/channels", GroupController, :create_channel
    post "/groups/:id/read", GroupController, :mark_read
    get "/friends", SocialController, :index
    post "/friends", SocialController, :mutate
    get "/friends/events", SocialController, :events
    get "/groups/:id/events", GroupController, :events
    put "/groups/:id/events/:type/:txn_id", GroupController, :send_event
    get "/me", V1Controller, :me
    get "/chats", V1Controller, :chats
    get "/chats/:id/events", V1Controller, :list_events
    post "/chats/:id/events", V1Controller, :create_event
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

    resources "/services", ServiceController, only: [:index, :create, :delete]
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
    get "/v3/rooms/:roomId/messages", ClientController, :messages
  end

  scope "/_matrix/media", LakehouseWeb.Matrix, as: :matrix_media do
    pipe_through [:api, LakehouseWeb.Plugs.MatrixAuth]

    post "/v3/upload", MediaController, :upload
    get "/v3/download/:serverName/:mediaId", MediaController, :download
  end
end
