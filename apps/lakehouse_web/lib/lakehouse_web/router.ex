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

  pipeline :matrix_optional do
    plug LakehouseWeb.Plugs.MatrixAuth, optional: true
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
    get "/_matrix/client/v3/login/sso/redirect", Matrix.SsoController, :start
    get "/_matrix/client/v3/login/sso/redirect/:idpId", Matrix.SsoController, :start
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

    get "/contacts", ContactsController, :index
    post "/contacts", ContactsController, :mutate

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
    get "/matrix/sso/consent", Matrix.SsoController, :consent
    post "/matrix/sso/consent", Matrix.SsoController, :approve

    get "/profile/password", SettingsController, :redirect_legacy
    get "/admin", SettingsController, :redirect_legacy
  end

  # --- iam-server compatible JSON API (no CSRF) ---
  scope "/", LakehouseWeb do
    pipe_through :api

    get "/public/v1/posts/:event", App.PublishingController, :show
    get "/public/v1/spaces/:id/posts", App.PublishingController, :blog
    get "/rtc/leases/:id", App.RtcController, :lease
    get "/healthz", DiscoveryController, :health
    get "/readyz", DiscoveryController, :ready
    get "/.well-known/webfinger", DiscoveryController, :webfinger
    get "/.well-known/iam-configuration", DiscoveryController, :configuration
    get "/.well-known/matrix/client", DiscoveryController, :matrix_client
    get "/.well-known/matrix/server", DiscoveryController, :matrix_server

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

    post "/groups/:id/publication", PublishingController, :policy
    post "/posts/:event/comment", PublishingController, :comment
    post "/posts/:event/reactions", PublishingController, :reaction
    get "/rtc", RtcController, :capabilities
    get "/calls", RtcController, :index
    post "/groups/:id/rtc", RtcController, :update
    get "/groups/:id/files", WorkspaceController, :files
    get "/home", WorkspaceController, :home
    post "/conversations", WorkspaceController, :conversation
    post "/groups/:id/invitations", WorkspaceController, :invite
    post "/groups/:id/entry/read", WorkspaceController, :read
    get "/live", LiveController, :events
    get "/presence", LiveController, :presence
    get "/overview", GroupController, :overview
    get "/groups", GroupController, :index
    post "/groups", GroupController, :create
    post "/direct", GroupController, :direct
    post "/groups/:id/membership", GroupController, :membership
    patch "/groups/:id", GroupController, :update
    get "/groups/:id/channels", GroupController, :channels
    post "/groups/:id/channels", GroupController, :create_channel
    post "/groups/:id/read", GroupController, :mark_read
    get "/contacts", ContactsController, :index
    post "/contacts", ContactsController, :mutate
    get "/contacts/events", ContactsController, :events
    get "/friends", SocialController, :index
    post "/friends", SocialController, :mutate
    get "/friends/events", SocialController, :events
    get "/groups/:id/entries", RiverContentController, :entries
    get "/groups/:id/thread", RiverContentController, :thread
    post "/groups/:id/reactions", RiverContentController, :reaction
    post "/groups/:id/entry", RiverContentController, :edit
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
    pipe_through [:api, :matrix_optional]

    get "/versions", ClientController, :versions
    get "/v3/directory/room/:roomAlias", ProtocolController, :resolve_alias
    get "/v3/directory/list/room/:roomId", ProtocolController, :directory_visibility
    get "/v3/publicRooms", ProtocolController, :public_rooms
    get "/v3/login", ProtocolController, :login_flows
    post "/v3/login", ProtocolController, :login
    post "/v3/refresh", ProtocolController, :refresh
    post "/v3/register", AccountPolicyController, :registration
    get "/v3/register/available", AccountPolicyController, :registration
    post "/v3/register/email/requestToken", AccountPolicyController, :registration
    post "/v3/register/msisdn/requestToken", AccountPolicyController, :registration
    get "/v1/register/m.login.registration_token/validity", AccountPolicyController, :registration
    post "/v3/account/password/email/requestToken", AccountPolicyController, :password
    post "/v3/account/password/msisdn/requestToken", AccountPolicyController, :password
    get "/v3/profile/:userId", ProtocolController, :profile
    get "/v3/profile/:userId/:field", ProtocolController, :profile
  end

  scope "/_matrix/client", LakehouseWeb.Matrix, as: :matrix do
    pipe_through [:api, LakehouseWeb.Plugs.MatrixAuth]

    put "/v3/rooms/:roomId/typing/:userId", ProtocolController, :typing
    put "/v3/presence/:userId/status", ProtocolController, :presence
    get "/v3/presence/:userId/status", ProtocolController, :presence
    get "/v3/sync", ProtocolController, :sync
    post "/unstable/org.matrix.msc4186/sync", ProtocolController, :sliding_sync
    post "/v4/sync", ProtocolController, :sliding_sync
    put "/v3/profile/:userId/:field", ProtocolController, :set_profile
    delete "/v3/profile/:userId/:field", ProtocolController, :set_profile
    post "/v3/user_directory/search", ProtocolController, :user_directory
    get "/v1/mutual_rooms", ProtocolController, :mutual_rooms
    get "/v3/account/whoami", ProtocolController, :whoami
    post "/v3/user/:userId/openid/request_token", ProtocolController, :openid_token
    post "/v3/rooms/:roomId/report/:eventId", ProtocolController, :report
    post "/v3/rooms/:roomId/report", ProtocolController, :report
    post "/v3/users/:userId/report", ProtocolController, :report
    post "/v3/logout", ProtocolController, :logout
    post "/v3/logout/all", ProtocolController, :logout_all
    post "/v1/login/get_token", ProtocolController, :login_token
    get "/v3/capabilities", ProtocolController, :capabilities
    get "/v3/admin/whois/:userId", AdminController, :whois
    get "/v1/admin/lock/:userId", AdminController, :locked
    put "/v1/admin/lock/:userId", AdminController, :locked
    get "/v1/admin/suspend/:userId", AdminController, :suspended
    put "/v1/admin/suspend/:userId", AdminController, :suspended
    get "/v3/devices", ProtocolController, :devices
    get "/v3/devices/:device", ProtocolController, :get_device
    put "/v3/devices/:device", ProtocolController, :update_device
    delete "/v3/devices/:device", ProtocolController, :delete_device
    post "/v3/delete_devices", ProtocolController, :delete_devices
    put "/v3/directory/room/:roomAlias", ProtocolController, :set_alias
    delete "/v3/directory/room/:roomAlias", ProtocolController, :delete_alias
    put "/v3/directory/list/room/:roomId", ProtocolController, :set_directory_visibility
    post "/v3/publicRooms", ProtocolController, :public_rooms
    get "/v3/rooms/:roomId/aliases", ProtocolController, :local_aliases
    get "/v3/joined_rooms", ProtocolController, :joined_rooms
    post "/v3/rooms/:roomId/join", ClientController, :join_room_id
    get "/v3/rooms/:roomId/state", ProtocolController, :get_state
    get "/v3/rooms/:roomId/state/:eventType", ProtocolController, :get_state
    get "/v3/rooms/:roomId/state/:eventType/:stateKey", ProtocolController, :get_state
    put "/v3/rooms/:roomId/state/:eventType/:stateKey", ProtocolController, :put_state
    get "/v3/rooms/:roomId/event/:eventId", ProtocolController, :event
    get "/v1/rooms/:roomId/hierarchy", ProtocolController, :space_hierarchy
    get "/v1/rooms/:roomId/timestamp_to_event", ProtocolController, :timestamp_to_event
    get "/v1/room_summary/:roomIdOrAlias", ProtocolController, :room_summary
    post "/v3/rooms/:roomId/upgrade", ProtocolController, :upgrade_room
    get "/v1/rooms/:roomId/relations/:eventId", ProtocolController, :relations
    get "/v1/rooms/:roomId/relations/:eventId/:relType", ProtocolController, :relations
    get "/v1/rooms/:roomId/relations/:eventId/:relType/:eventType", ProtocolController, :relations
    get "/v1/rooms/:roomId/threads", ProtocolController, :threads
    get "/v3/rooms/:roomId/context/:eventId", ProtocolController, :context
    get "/v3/rooms/:roomId/members", ProtocolController, :members
    get "/v3/rooms/:roomId/joined_members", ProtocolController, :joined_members
    put "/v3/rooms/:roomId/redact/:eventId/:txnId", ProtocolController, :redact
    post "/v3/rooms/:roomId/receipt/:receiptType/:eventId", ProtocolController, :receipt
    post "/v3/rooms/:roomId/read_markers", ProtocolController, :read_markers
    get "/v3/user/:userId/account_data/:type", ProtocolController, :get_data
    put "/v3/user/:userId/account_data/:type", ProtocolController, :put_data
    get "/v3/user/:userId/rooms/:roomId/account_data/:type", ProtocolController, :get_data
    put "/v3/user/:userId/rooms/:roomId/account_data/:type", ProtocolController, :put_data
    get "/v3/user/:userId/rooms/:roomId/tags", ProtocolController, :tags
    put "/v3/user/:userId/rooms/:roomId/tags/:tag", ProtocolController, :tags
    delete "/v3/user/:userId/rooms/:roomId/tags/:tag", ProtocolController, :tags
    post "/v3/user/:userId/filter", ProtocolController, :create_filter
    get "/v3/user/:userId/filter/:filterId", ProtocolController, :get_filter
    put "/v3/sendToDevice/:eventType/:txnId", ProtocolController, :send_to_device
    post "/v3/keys/upload", ProtocolController, :keys_upload
    post "/v3/keys/query", ProtocolController, :keys_query
    post "/v3/keys/claim", ProtocolController, :keys_claim
    post "/v3/keys/device_signing/upload", ProtocolController, :cross_signing_upload
    post "/v3/keys/signatures/upload", ProtocolController, :signatures_upload
    get "/v3/keys/changes", ProtocolController, :key_changes
    get "/v3/room_keys/version", ProtocolController, :backup_version
    post "/v3/room_keys/version", ProtocolController, :backup_version
    get "/v3/room_keys/version/:version", ProtocolController, :backup_version
    put "/v3/room_keys/version/:version", ProtocolController, :backup_version
    delete "/v3/room_keys/version/:version", ProtocolController, :backup_version
    get "/v3/room_keys/keys", ProtocolController, :backup_keys
    put "/v3/room_keys/keys", ProtocolController, :backup_keys
    delete "/v3/room_keys/keys", ProtocolController, :backup_keys
    get "/v3/room_keys/keys/:roomId", ProtocolController, :backup_keys
    put "/v3/room_keys/keys/:roomId", ProtocolController, :backup_keys
    delete "/v3/room_keys/keys/:roomId", ProtocolController, :backup_keys
    get "/v3/room_keys/keys/:roomId/:sessionId", ProtocolController, :backup_keys
    put "/v3/room_keys/keys/:roomId/:sessionId", ProtocolController, :backup_keys
    delete "/v3/room_keys/keys/:roomId/:sessionId", ProtocolController, :backup_keys
    get "/v3/pushrules/", ProtocolController, :pushrules
    get "/v3/pushrules/:scope/", ProtocolController, :pushrules
    get "/v3/pushrules/:scope/:kind/:ruleId", ProtocolController, :pushrules
    put "/v3/pushrules/:scope/:kind/:ruleId", ProtocolController, :pushrules
    delete "/v3/pushrules/:scope/:kind/:ruleId", ProtocolController, :pushrules
    get "/v3/pushrules/:scope/:kind/:ruleId/:field", ProtocolController, :pushrules
    put "/v3/pushrules/:scope/:kind/:ruleId/:field", ProtocolController, :pushrules
    get "/v3/notifications", ProtocolController, :notifications
    get "/v3/pushers", ProtocolController, :pushers
    post "/v3/pushers/set", ProtocolController, :pushers
    get "/v1/media/config", ProtocolController, :media_config
    get "/v1/media/download/:serverName/:mediaId", MediaController, :download
    get "/v1/media/download/:serverName/:mediaId/:fileName", MediaController, :download
    get "/v1/media/thumbnail/:serverName/:mediaId", MediaController, :thumbnail

    post "/v3/createRoom", ProtocolController, :create_room
    post "/v3/join/:roomIdOrAlias", ClientController, :join_room
    post "/v3/knock/:roomIdOrAlias", ProtocolController, :knock
    post "/v3/rooms/:roomId/invite", ClientController, :invite
    post "/v3/rooms/:roomId/leave", ClientController, :leave_room
    post "/v3/rooms/:roomId/forget", ProtocolController, :forget
    post "/v3/rooms/:roomId/kick", ProtocolController, :moderate
    post "/v3/rooms/:roomId/ban", ProtocolController, :moderate
    post "/v3/rooms/:roomId/unban", ProtocolController, :moderate
    put "/v3/rooms/:roomId/send/:eventType/:txnId", ProtocolController, :send_event
    put "/v3/rooms/:roomId/state/:eventType", ProtocolController, :put_state
    get "/v3/rooms/:roomId/messages", ProtocolController, :messages
    post "/v3/search", ProtocolController, :search
    post "/v3/account/password", AccountPolicyController, :password
    get "/v3/account/3pid", AccountPolicyController, :threepids
    post "/v3/account/3pid", AccountPolicyController, :threepids
    post "/v3/account/3pid/add", AccountPolicyController, :threepids
    post "/v3/account/3pid/bind", AccountPolicyController, :threepids
    post "/v3/account/3pid/delete", AccountPolicyController, :threepids
    post "/v3/account/3pid/unbind", AccountPolicyController, :threepids
    post "/v3/account/3pid/email/requestToken", AccountPolicyController, :threepids
    post "/v3/account/3pid/msisdn/requestToken", AccountPolicyController, :threepids
    get "/v3/thirdparty/protocols", AccountPolicyController, :protocols
    get "/v3/thirdparty/protocol/:protocol", AccountPolicyController, :thirdparty
    get "/v3/thirdparty/location/:protocol", AccountPolicyController, :thirdparty
    get "/v3/thirdparty/user/:protocol", AccountPolicyController, :thirdparty
    get "/v3/thirdparty/location", AccountPolicyController, :thirdparty
    get "/v3/thirdparty/user", AccountPolicyController, :thirdparty
    get "/v3/voip/turnServer", AccountPolicyController, :turn
    get "/v1/media/preview_url", MediaController, :preview
  end

  scope "/_matrix/media", LakehouseWeb.Matrix, as: :matrix_media do
    pipe_through [:api, LakehouseWeb.Plugs.MatrixAuth]

    post "/v3/upload", MediaController, :upload
    get "/v3/preview_url", MediaController, :preview
    post "/v1/create", MediaController, :create
    put "/v3/upload/:serverName/:mediaId", MediaController, :upload_reserved
    get "/v3/download/:serverName/:mediaId", MediaController, :download
    get "/v3/download/:serverName/:mediaId/:fileName", MediaController, :download
    get "/v3/thumbnail/:serverName/:mediaId", MediaController, :thumbnail
    get "/v3/config", ProtocolController, :media_config
  end

  scope "/_matrix", LakehouseWeb.Matrix do
    get "/federation/v1/version", FederationController, :version
    get "/key/v2/server", FederationController, :server_keys
    get "/key/v2/server/:keyId", FederationController, :server_keys
    get "/key/v2/query/:serverName", FederationController, :query_keys
    get "/key/v2/query/:serverName/:keyId", FederationController, :query_keys
    post "/key/v2/query", FederationController, :query_keys
  end

  scope "/_matrix/federation", LakehouseWeb.Matrix do
    pipe_through :api
    get "/v1/openid/userinfo", FederationController, :openid_userinfo
  end

  scope "/_matrix/federation", LakehouseWeb.Matrix do
    pipe_through [:api, LakehouseWeb.Plugs.FederationAuth]
    get "/v1/media/download/:mediaId", MediaController, :federation
    get "/v1/media/thumbnail/:mediaId", MediaController, :federation
    get "/v1/query/profile", FederationController, :profile
    get "/v1/query/directory", FederationController, :directory
    get "/v1/publicRooms", FederationController, :public_rooms
    get "/v1/hierarchy/:roomId", FederationController, :space_hierarchy
    get "/v1/timestamp_to_event/:roomId", FederationController, :timestamp_to_event
    post "/v1/publicRooms", FederationController, :public_rooms
    get "/v1/user/devices/:userId", FederationController, :user_devices
    post "/v1/user/keys/query", FederationController, :keys_query
    post "/v1/user/keys/claim", FederationController, :keys_claim
    get "/v1/make_join/:roomId/:userId", FederationController, :make_membership
    get "/v1/make_leave/:roomId/:userId", FederationController, :make_membership
    get "/v1/make_knock/:roomId/:userId", FederationController, :make_membership
    put "/v1/send_join/:roomId/:eventId", FederationController, :send_membership
    put "/v2/send_join/:roomId/:eventId", FederationController, :send_membership
    put "/v1/send_leave/:roomId/:eventId", FederationController, :send_membership
    put "/v2/send_leave/:roomId/:eventId", FederationController, :send_membership
    put "/v2/invite/:roomId/:eventId", FederationController, :invite
    put "/v1/send_knock/:roomId/:eventId", FederationController, :send_membership
    get "/v1/event/:eventId", FederationController, :event
    get "/v1/event_auth/:roomId/:eventId", FederationController, :event_auth
    get "/v1/state/:roomId", FederationController, :room_state
    get "/v1/state_ids/:roomId", FederationController, :room_state
    get "/v1/backfill/:roomId", FederationController, :backfill
    post "/v1/get_missing_events/:roomId", FederationController, :missing
    put "/v1/send/:txnId", FederationController, :transaction
  end

  scope "/_matrix", LakehouseWeb.Matrix do
    match :*, "/*path", ProtocolController, :unrecognized
  end
end
