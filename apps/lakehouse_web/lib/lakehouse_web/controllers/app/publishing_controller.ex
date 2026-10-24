defmodule LakehouseWeb.App.PublishingController do
  use LakehouseWeb, :controller
  alias LakehouseMatrix.RiverPublishing
  alias LakehouseIam.Apps.Tokens
  def policy(conn, %{"id" => id} = p), do: respond(conn, RiverPublishing.policy(conn.assigns.app_grant, id, p))
  def comment(conn, %{"event" => event} = p), do: respond(conn, RiverPublishing.comment(conn.assigns.app_grant, event, p))
  def reaction(conn, %{"event" => event} = p), do: respond(conn, RiverPublishing.reaction(conn.assigns.app_grant, event, p))
  def show(conn, %{"event" => event} = p), do: respond(conn, RiverPublishing.show(optional_grant(conn), event, p))
  def blog(conn, %{"id" => id} = p), do: respond(conn, RiverPublishing.blog(optional_grant(conn), id, p))
  defp optional_grant(conn) do
    with ["Bearer " <> token] <- get_req_header(conn,"authorization"), {:ok,%{grant: g, token: t}} <- Tokens.verify_access(token) do
      %{g | scopes: Tokens.effective_scopes(t,g)}
    else
      _ -> nil
    end
  end
  defp respond(conn, {:ok, body}), do: conn |> put_resp_header("cache-control","no-store") |> json(body)
  defp respond(conn, {:error, reason}) do
    status = cond do
      reason in [:forbidden,:insufficient_scope] -> 403
      reason == :not_found -> 404
      reason == :transaction_conflict -> 409
      true -> 400
    end
    conn |> put_status(status) |> json(%{error: to_string(reason)})
  end
end
