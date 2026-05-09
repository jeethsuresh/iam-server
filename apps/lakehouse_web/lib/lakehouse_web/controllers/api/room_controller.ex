defmodule LakehouseWeb.Api.RoomController do
  use LakehouseWeb, :controller

  alias LakehouseMatrix.Rooms

  def index(conn, _params) do
    rooms = Rooms.list_rooms()
    json(conn, Enum.map(rooms, &room_json/1))
  end

  def create(conn, params) do
    case Rooms.create_room(%{
           name: params["name"] || "Room",
           topic: params["topic"],
           alias: params["alias"]
         }) do
      {:ok, room} ->
        conn
        |> put_status(:created)
        |> json(room_json(room))

      {:error, cs} ->
        conn |> put_status(:bad_request) |> json(%{errors: translate_errors(cs)})
    end
  end

  def show(conn, %{"id" => id}) do
    case Rooms.get_room(id) do
      nil ->
        conn |> put_status(:not_found) |> json(%{error: "not_found"})

      room ->
        _ = Rooms.ensure_started(room.id)
        json(conn, room_json(room))
    end
  end

  defp room_json(room) do
    %{
      id: room.id,
      name: room.name,
      topic: room.topic,
      alias: room.alias,
      inserted_at: room.inserted_at
    }
  end

  defp translate_errors(cs) do
    Ecto.Changeset.traverse_errors(cs, fn {msg, opts} ->
      Enum.reduce(opts, msg, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
  end
end
