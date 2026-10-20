defmodule LakehouseAppDemo.Router do
  use Phoenix.Router

  import Plug.Conn
  import Phoenix.Controller

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :protect_from_forgery
    plug :put_secure_browser_headers
  end

  scope "/", LakehouseAppDemo do
    pipe_through :browser

    get "/", PageController, :index
    get "/auth/gravitas/start", PageController, :launch
    post "/login", PageController, :start_login
    get "/oauth/callback", PageController, :callback
    get "/logout", PageController, :logout
    post "/chats/:id/events", PageController, :send_event
  end
end
