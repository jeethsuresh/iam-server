defmodule LakehouseWeb.Router do
  use LakehouseWeb, :router

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_flash
    plug :put_root_layout, html: {LakehouseWeb.Layouts, :root}
    plug :protect_from_forgery
    plug :put_secure_browser_headers
  end

  pipeline :browser_session do
    plug :accepts, ["html", "json"]
    plug :fetch_session
    plug :fetch_flash
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
    pipe_through [:browser_session, :session_authenticated]

    get "/profile", IamProfileController, :show
    get "/profile/password", ProfilePasswordController, :edit
    post "/web/profile/password", ProfilePasswordController, :update_browser
  end

  scope "/", LakehouseWeb do
    pipe_through [:browser, :session_authenticated, :require_admin]

    get "/admin", AdminController, :index
    post "/web/admin/approve", AdminController, :approve
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
end
