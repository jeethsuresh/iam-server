defmodule LakehouseWeb.App.V1Controller do
  use LakehouseWeb, :controller

  alias LakehouseIam.Apps.Grants
  alias LakehouseIam.Repo
  alias LakehouseIam.Schema.Principal
  alias LakehouseMatrix.{Events, Matrix, Memberships}

  def me(conn, _params) do
    with :ok <- require_scope(conn, "profile.name"),
         %Principal{} = p <- Repo.get(Principal, conn.assigns.principal_id) do
      json(conn, %{username: p.username, name: p.username})
    else
      {:error, :forbidden} -> forbidden(conn, "profile.name")
      _ -> conn |> put_status(404) |> json(%{error: "not_found"})
    end
  end

  def chats(conn, _params) do
    with :ok <- require_scope(conn, "chats.list") do
      rooms =
        Memberships.list_joined_rooms(conn.assigns.principal_id)
        |> Enum.map(fn r -> %{id: r.id, name: r.name} end)

      json(conn, %{chats: rooms})
    else
      {:error, :forbidden} -> forbidden(conn, "chats.list")
    end
  end

  def list_events(conn, %{"id" => room_id} = params) do
    with :ok <- require_scope(conn, "chats.read"),
         :ok <- require_room(conn, room_id),
         true <- Memberships.joined?(room_id, conn.assigns.principal_id) do
      opts = [limit: parse_int(params["limit"], 50)]

      opts =
        case Integer.parse(params["from"] || "") do
          {ts, _} -> Keyword.put(opts, :from_ts, ts)
          :error -> opts
        end

      events = Events.list_timeline(room_id, opts)
      json(conn, %{events: events})
    else
      {:error, :forbidden} -> forbidden(conn, "chats.read")
      false -> conn |> put_status(403) |> json(%{error: "not_a_member"})
      _ -> conn |> put_status(403) |> json(%{error: "room_not_allowed"})
    end
  end

  def create_event(conn, %{"id" => room_id} = params) do
    with :ok <- require_scope(conn, "chats.write"),
         :ok <- require_room(conn, room_id),
         body when is_binary(body) and body != "" <- params["body"] || get_in(params, ["content", "body"]),
         txn_id <- params["txn_id"] || Ecto.UUID.generate(),
         {:ok, event} <-
           Matrix.send_message(conn.assigns.principal_id, room_id, txn_id, %{
             "msgtype" => "m.text",
             "body" => body
           }) do
      json(conn, %{
        event: %{
          event_id: Map.get(event, :event_id) || Map.get(event, "event_id"),
          type: Map.get(event, :type) || "m.room.message",
          room_id: room_id,
          content: %{msgtype: "m.text", body: body}
        }
      })
    else
      {:error, :forbidden} ->
        forbidden(conn, "chats.write")

      {:error, reason} ->
        conn |> put_status(403) |> json(%{error: to_string(reason)})

      nil ->
        conn |> put_status(400) |> json(%{error: "body required"})

      "" ->
        conn |> put_status(400) |> json(%{error: "body required"})

      _ ->
        conn |> put_status(403) |> json(%{error: "room_not_allowed"})
    end
  end

  defp require_scope(conn, scope) do
    grant = conn.assigns.app_grant

    if scope in grant.scopes do
      :ok
    else
      {:error, :forbidden}
    end
  end

  defp require_room(conn, room_id) do
    if Grants.room_allowed?(conn.assigns.app_grant, room_id) do
      :ok
    else
      {:error, :room_not_allowed}
    end
  end

  defp forbidden(conn, scope) do
    conn |> put_status(403) |> json(%{error: "insufficient_scope", scope: scope})
  end

  defp parse_int(nil, default), do: default

  defp parse_int(str, default) do
    case Integer.parse(to_string(str)) do
      {n, _} -> n
      :error -> default
    end
  end
end
