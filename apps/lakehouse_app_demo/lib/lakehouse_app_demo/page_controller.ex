defmodule LakehouseAppDemo.PageController do
  use Phoenix.Controller, formats: [:html]

  import Plug.Conn

  alias LakehouseAppDemo.OAuthClient

  @default_scopes "profile.name chats.list chats.read chats.write"

  def index(conn, _params) do
    access = get_session(conn, :access_token)
    iam_base = get_session(conn, :iam_base)

    if access && iam_base do
      me = OAuthClient.api_get(iam_base, "/app/v1/me", access)
      chats = OAuthClient.api_get(iam_base, "/app/v1/chats", access)

      {events, selected} =
        case chats do
          {:ok, %{"chats" => [first | _]}} ->
            ev = OAuthClient.api_get(iam_base, "/app/v1/chats/#{first["id"]}/events", access)
            {ev, first["id"]}

          _ ->
            {{:ok, %{"events" => []}}, nil}
        end

      html(conn, home_html(me, chats, events, selected, get_session(conn, :flash_error)))
    else
      html(conn, login_html(get_session(conn, :flash_error), get_csrf_token()))
    end
  end

  def start_login(conn, %{"username" => username_at}) do
    with {:ok, local, iam_base} <- resolve_iam(username_at),
         caller <- public_url(conn, "/"),
         redirect_uri <- public_url(conn, "/oauth/callback"),
         {:ok, start} <-
           OAuthClient.start_login(iam_base, local, caller, redirect_uri, @default_scopes) do
      conn
      |> put_session(:pkce_verifier, start.verifier)
      |> put_session(:oauth_state, start.state)
      |> put_session(:iam_base, iam_base)
      |> put_session(:redirect_uri, redirect_uri)
      |> redirect(external: start.authorize_url)
    else
      {:error, msg} ->
        conn
        |> put_session(:flash_error, to_string(msg))
        |> redirect(to: "/")
    end
  end

  def callback(conn, params) do
    with true <- params["state"] == get_session(conn, :oauth_state),
         verifier when is_binary(verifier) <- get_session(conn, :pkce_verifier),
         iam_base when is_binary(iam_base) <- get_session(conn, :iam_base),
         redirect_uri when is_binary(redirect_uri) <- get_session(conn, :redirect_uri),
         {:ok, tokens} <-
           OAuthClient.exchange_token(iam_base, params["code"], verifier, redirect_uri) do
      conn
      |> put_session(:access_token, tokens["access_token"])
      |> put_session(:refresh_token, tokens["refresh_token"])
      |> delete_session(:pkce_verifier)
      |> delete_session(:oauth_state)
      |> delete_session(:flash_error)
      |> redirect(to: "/")
    else
      _ ->
        conn
        |> put_session(:flash_error, "OAuth callback failed")
        |> redirect(to: "/")
    end
  end

  def logout(conn, _params) do
    conn
    |> configure_session(drop: true)
    |> redirect(to: "/")
  end

  def send_event(conn, %{"id" => room_id, "body" => body}) do
    access = get_session(conn, :access_token)
    iam_base = get_session(conn, :iam_base)

    case OAuthClient.api_post(iam_base, "/app/v1/chats/#{room_id}/events", access, %{body: body}) do
      {:ok, _} -> redirect(conn, to: "/")
      {:error, msg} -> conn |> put_session(:flash_error, msg) |> redirect(to: "/")
    end
  end

  defp resolve_iam(username_at) do
    case Application.get_env(:lakehouse_app_demo, :iam_base) do
      base when is_binary(base) and base != "" ->
        case OAuthClient.parse_username_at_host(username_at) do
          {:ok, local, _} -> {:ok, local, String.trim_trailing(base, "/")}
          err -> err
        end

      _ ->
        with {:ok, identity, metadata} <- LakehouseIam.Discovery.resolve(username_at) do
          {:ok, identity.user_id, metadata}
        end
    end
  end

  defp public_url(conn, path) do
    conf = Application.get_env(:lakehouse_app_demo, LakehouseAppDemo.Endpoint)
    url = Keyword.get(conf, :url, [])
    host = Keyword.get(url, :host, "127.0.0.1")
    port = Keyword.get(url, :port) || conn.port
    scheme = Keyword.get(url, :scheme, "http")
    "#{scheme}://#{host}:#{port}#{path}"
  end

  defp login_html(error, csrf) do
    err =
      if error,
        do: "<p style=\"color:red\">#{Plug.HTML.html_escape(to_string(error))}</p>",
        else: ""

    """
    <!DOCTYPE html><html><head><title>App Demo</title></head><body>
    <h1>Lakehouse App Demo</h1>
    #{err}
    <form method="post" action="/login">
      <input type="hidden" name="_csrf_token" value="#{Plug.HTML.html_escape(csrf)}" />
      <label>Lakehouse @username:domain
        <input name="username" placeholder="@alice:example.com" required />
      </label>
      <button type="submit">Continue</button>
    </form>
    </body></html>
    """
  end

  defp home_html(me, chats, events, selected, error) do
    err =
      if error,
        do: "<p style=\"color:red\">#{Plug.HTML.html_escape(to_string(error))}</p>",
        else: ""

    name =
      case me do
        {:ok, %{"name" => n}} -> n
        _ -> "(no profile scope or error)"
      end

    chat_list =
      case chats do
        {:ok, %{"chats" => list}} ->
          Enum.map_join(list, "", fn c ->
            "<li>#{Plug.HTML.html_escape(to_string(c["name"] || c["id"]))}</li>"
          end)

        {:error, e} ->
          "<li>#{Plug.HTML.html_escape(to_string(e))}</li>"
      end

    event_list =
      case events do
        {:ok, %{"events" => list}} ->
          Enum.map_join(list, "", fn e ->
            body = get_in(e, ["content", "body"]) || inspect(e)
            "<li>#{Plug.HTML.html_escape(to_string(body))}</li>"
          end)

        {:error, e} ->
          "<li>#{Plug.HTML.html_escape(to_string(e))}</li>"
      end

    compose =
      if selected do
        csrf = Plug.CSRFProtection.get_csrf_token()

        """
        <form method="post" action="/chats/#{selected}/events">
          <input type="hidden" name="_csrf_token" value="#{Plug.HTML.html_escape(csrf)}" />
          <input name="body" placeholder="Write a message" required />
          <button type="submit">Send</button>
        </form>
        """
      else
        ""
      end

    """
    <!DOCTYPE html><html><head><title>App Demo</title></head><body>
    <h1>Signed in</h1>
    #{err}
    <p>Name: <strong>#{Plug.HTML.html_escape(to_string(name))}</strong></p>
    <p><a href="/logout">Sign out</a></p>
    <h2>Chats</h2>
    <ul>#{chat_list}</ul>
    <h2>Events</h2>
    <ul>#{event_list}</ul>
    #{compose}
    </body></html>
    """
  end
end
