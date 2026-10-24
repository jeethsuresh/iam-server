defmodule LakehouseWeb.App.RiverContentController do
  use LakehouseWeb, :controller
  alias LakehouseMatrix.RiverContent
  def entries(conn, %{"id" => id} = p), do: respond(conn, RiverContent.entries(conn.assigns.app_grant, id, p))
  def thread(conn, %{"id" => id} = p), do: respond(conn, RiverContent.thread(conn.assigns.app_grant, id, p))
  def reaction(conn, %{"id" => id} = p), do: respond(conn, RiverContent.reaction(conn.assigns.app_grant, id, p))
  def edit(conn, %{"id" => id} = p), do: respond(conn, RiverContent.edit(conn.assigns.app_grant, id, p))
  defp respond(conn, {:ok, body}), do: json(conn, body)
  defp respond(conn, {:error, reason}) do
    status = case reason do
      r when r in [:forbidden, :insufficient_scope] -> 403
      :transaction_conflict -> 409
      _ -> 400
    end
    conn |> put_status(status) |> json(%{error: to_string(reason)})
  end
end
