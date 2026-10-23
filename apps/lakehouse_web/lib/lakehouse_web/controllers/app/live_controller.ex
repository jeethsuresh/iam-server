defmodule LakehouseWeb.App.LiveController do
  use LakehouseWeb, :controller
  alias LakehouseIam.{Changes, Contacts}
  alias LakehouseIam.Apps.Tokens
  alias LakehouseMatrix.DelegatedGroups

  def events(conn, _) do
    g = conn.assigns.app_grant
    with true <- "chats.list" in g.scopes,
         :ok <- Changes.subscribe(g.principal_id, g.app_origin) do
      ["Bearer " <> token] = get_req_header(conn, "authorization")
      conn = conn |> put_resp_header("cache-control", "no-store")
        |> put_resp_header("x-accel-buffering", "no")
        |> put_resp_content_type("text/event-stream") |> send_chunked(200)
      case chunk(conn, "event: ready\ndata: {}\n\n") do
        {:ok, conn} -> stream(conn, token)
        _ -> conn
      end
    else
      _ -> conn |> put_status(403) |> json(%{error: "forbidden"})
    end
  end

  def presence(conn, _) do
    g = conn.assigns.app_grant
    case Contacts.list(g) do
      {:ok, social} -> json(conn, %{online: for(p <- social.contacts, p.uses_app and Changes.online?(p.principal_id, g.app_origin), do: LakehouseMatrix.Identity.user_id(p.username))})
      {:error, _} -> conn |> put_status(403) |> json(%{error: "insufficient_scope"})
    end
  end

  defp stream(conn, token) do
    receive do
      {:gravitas_change, change} ->
        case current(token) do
          {:ok, g} ->
            if visible?(g, change) do
              case chunk(conn, "event: invalidate\ndata: {}\n\n") do
                {:ok, next} -> stream(next, token)
                _ -> conn
              end
            else
              stream(conn, token)
            end
          _ -> revoke(conn)
        end
    after
      10_000 ->
        case current(token) do
          {:ok, _} ->
            case chunk(conn, ": heartbeat\n\n") do
              {:ok, next} -> stream(next, token)
              _ -> conn
            end
          _ -> revoke(conn)
        end
    end
  end
  defp current(token) do
    with {:ok, %{grant: g, token: t}} <- Tokens.verify_access(token),
         scopes = Tokens.effective_scopes(t, g), true <- "chats.list" in scopes do
      {:ok, %{g | scopes: scopes}}
    else
      _ -> :error
    end
  end
  defp visible?(g, %{"room_id" => id} = change) do
    change["member"] == LakehouseIam.Identifier.format(LakehouseIam.Repo.get!(LakehouseIam.Schema.Principal, g.principal_id).username) or DelegatedGroups.visible?(g, id)
  end
  defp visible?(g, %{"principal_id" => id}) do
    id == g.principal_id or ("contacts.read" in g.scopes and Contacts.connected?(g.principal_id, id) and Contacts.available_in_app?(id, g.app_origin))
  end
  defp visible?(g, %{"principals" => ids}), do: g.principal_id in ids
  defp visible?(_, _), do: false
  defp revoke(conn) do
    case chunk(conn, "event: revoked\ndata: {}\n\n") do
      {:ok, next} -> next
      _ -> conn
    end
  end
end
