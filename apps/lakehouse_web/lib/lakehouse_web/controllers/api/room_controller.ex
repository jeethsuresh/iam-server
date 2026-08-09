defmodule LakehouseWeb.Api.RoomController do
  use LakehouseWeb, :controller

  alias LakehouseMatrix.{Identity, Matrix, Rooms}

  def index(conn, _params) do
    principal_id = conn.assigns[:principal_id]

    rooms =
      if principal_id do
        Rooms.list_rooms_for(principal_id)
      else
        Rooms.list_rooms()
      end

    json(conn, Enum.map(rooms, &room_json/1))
  end

  def create(conn, params) do
    principal_id = conn.assigns.principal_id

    matrix_params = %{
      "name" => params["name"] || "Room",
      "topic" => params["topic"],
      "room_alias_name" => params["alias"]
    }

    case Matrix.create_room(principal_id, matrix_params) do
      {:ok, %{"room_id" => matrix_room_id}} ->
        {:ok, room_uuid} = Identity.parse_room_id(matrix_room_id)
        room = Rooms.get_room(room_uuid)

        conn
        |> put_status(:created)
        |> json(room_json(room))

      {:error, :forbidden} ->
        conn |> put_status(:forbidden) |> json(%{error: "forbidden"})

      {:error, cs} when is_struct(cs, Ecto.Changeset) ->
        conn |> put_status(:bad_request) |> json(%{errors: translate_errors(cs)})

      {:error, _} ->
        conn |> put_status(:bad_request) |> json(%{error: "could_not_create_room"})
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
      inserted_at: room.inserted_at,
      matrix_room_id: Identity.room_id(room.id)
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
