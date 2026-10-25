defmodule LakehouseMatrix.Release do
  @moduledoc "Explicit maintenance release tasks; normal startup never resets room state."

  def room_reset_plan do
    load()

    {:ok, result, _} =
      Ecto.Migrator.with_repo(LakehouseIam.Repo, fn _ -> LakehouseMatrix.RoomReset.plan() end)

    result
  end

  def reset_rooms(expected_server) do
    if Enum.any?(Application.started_applications(), fn {app, _, _} ->
         app == :lakehouse_matrix
       end),
       do: raise("Stop Matrix application writers before running a room reset")

    load()

    {:ok, result, _} =
      Ecto.Migrator.with_repo(LakehouseIam.Repo, fn _ ->
        case LakehouseMatrix.RoomReset.run(expected_server) do
          {:ok, result} -> result
          {:error, reason} -> raise "Matrix room reset failed: #{inspect(reason)}"
        end
      end)

    result
  end

  defp load do
    Application.load(:lakehouse_iam)
    Application.load(:lakehouse_matrix)
  end
end
