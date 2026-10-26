defmodule LakehouseWeb.ProtocolController do
  use LakehouseWeb, :controller
  alias LakehouseIam.{Protocols, Repo}
  alias LakehouseIam.Apps.{Scopes, Tokens}
  alias LakehouseIam.Schema.AppGrant
  plug :private_response
  defp private_response(conn, _), do: put_resp_header(conn, "cache-control", "no-store")

  def register(conn, params) do
    grant = conn.assigns.app_grant

    if Scopes.covers?(grant.scopes, ["profile.name"]),
      do: result(conn, Protocols.register(grant, params), 204),
      else: error(conn, :forbidden)
  end

  # Backfill/reconciliation uses a status-only proof *plus* a trusted backend
  # credential. Neither credential alone can subscribe a different user/app.
  def register_service(conn, %{"session_proof" => proof, "registry" => registry}) do
    sender = conn.assigns.protocol_sender

    with true <- sender.service,
         {:ok, %{sub: subject, app_origin: origin}} <- Tokens.check_session(proof),
         true <- origin == sender.origin,
         %AppGrant{} = grant <- Repo.get_by(AppGrant, principal_id: subject, app_origin: origin) do
      result(conn, Protocols.register(grant, registry), 204)
    else
      _ -> error(conn, :forbidden)
    end
  end

  def register_service(conn, _), do: error(conn, :invalid_registry)

  def specifications(conn, _) do
    read(conn, fn sender -> %{"protocols" => Protocols.specifications(sender)} end)
  end

  def subscriptions(conn, %{"subject" => subject}) do
    read(conn, fn sender -> %{"protocols" => Protocols.subscribed(subject, sender)} end)
  end

  def invoke(conn, %{"subject" => subject} = params) do
    result(
      conn,
      Protocols.invoke(conn.assigns.protocol_sender, subject, Map.delete(params, "subject")),
      202
    )
  end

  defp read(conn, fun) do
    sender = conn.assigns.protocol_sender

    if "protocols.read" in sender.permissions,
      do: json(conn, fun.(sender)),
      else: error(conn, :forbidden)
  end

  defp result(conn, {:ok, _}, 204), do: send_resp(conn, 204, "")
  defp result(conn, {:ok, output}, status), do: conn |> put_status(status) |> json(output)
  defp result(conn, {:error, reason}, _), do: error(conn, reason)

  defp error(conn, reason) do
    status =
      case reason do
        :forbidden -> 403
        :invalid_or_forbidden -> 403
        :version_conflict -> 409
        :id_conflict -> 409
        :rate_limited -> 429
        _ -> 400
      end

    conn |> put_status(status) |> json(%{error: reason})
  end
end
