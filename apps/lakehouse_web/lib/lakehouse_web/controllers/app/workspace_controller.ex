defmodule LakehouseWeb.App.WorkspaceController do
  use LakehouseWeb, :controller
  alias LakehouseMatrix.RiverWorkspace, as: Workspace
  def home(conn, _), do: respond(conn, Workspace.home(conn.assigns.app_grant))
  def conversation(conn, p), do: respond(conn, Workspace.conversation(conn.assigns.app_grant, p))
  def invite(conn, %{"id" => id} = p), do: respond(conn, Workspace.invite(conn.assigns.app_grant, id, p))
  def read(conn, %{"id" => id} = p), do: respond(conn, Workspace.read_entry(conn.assigns.app_grant, id, p))
  defp respond(conn, {:ok, body}), do: json(conn, body)
  defp respond(conn, {:error, reason}) do
    status = cond do
      reason in [:forbidden, :insufficient_scope] -> 403
      reason == :transaction_conflict -> 409
      true -> 400
    end
    conn |> put_status(status) |> json(%{error: to_string(reason)})
  end
end
