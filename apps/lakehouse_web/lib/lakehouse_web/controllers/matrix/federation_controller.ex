defmodule LakehouseWeb.Matrix.FederationController do
  use LakehouseWeb, :controller
  alias LakehouseMatrix.{Federation.Signing, Identity}
  alias LakehouseWeb.Matrix.ProtocolController

  def version(conn, _),
    do: json(conn, %{"server" => %{"name" => "Gravitas", "version" => "0.1.0"}})

  def server_keys(conn, _) do
    case Signing.server_keys() do
      {:ok, keys} ->
        conn |> put_resp_header("cache-control", "public, max-age=3600") |> json(keys)

      _ ->
        ProtocolController.error(
          conn,
          503,
          "M_UNAVAILABLE",
          "Matrix signing key is not configured"
        )
    end
  end

  def query_keys(conn, params) do
    servers = params["server_keys"] || %{}

    wanted =
      params["serverName"] == Identity.homeserver_domain() or
        Map.has_key?(servers, Identity.homeserver_domain())

    case Signing.server_keys() do
      {:ok, keys} ->
        json(conn, %{"server_keys" => if(wanted, do: [keys], else: [])})

      _ ->
        ProtocolController.error(
          conn,
          503,
          "M_UNAVAILABLE",
          "Matrix signing key is not configured"
        )
    end
  end

  def profile(conn, %{"user_id" => user} = params) do
    with {:ok, local} <- Identity.parse_user_id(user),
         {:ok, p} <- LakehouseIam.Accounts.fetch_user(local),
         true <- p.active do
      fields = %{"displayname" => local, "avatar_url" => nil}
      json(conn, if(params["field"], do: Map.take(fields, [params["field"]]), else: fields))
    else
      _ -> ProtocolController.respond(conn, {:error, :not_found})
    end
  end

  def profile(conn, _), do: ProtocolController.respond(conn, {:error, :invalid_param})

  # Existing River events have neither a signed DAG nor event authorization
  # snapshots. Never accept remote PDUs into these local policy tables. The
  # explicit error makes this limitation visible to peers instead of ACKing and
  # silently losing a transaction, or trusting an IAM bearer as federation auth.
  def transaction(conn, params) do
    pdus = params["pdus"] || []
    edus = params["edus"] || []

    if params["origin"] == conn.assigns.matrix_origin and is_list(pdus) and length(pdus) <= 50 and
         is_list(edus) and length(edus) <= 100 do
      ProtocolController.error(
        conn,
        501,
        "M_UNRECOGNIZED",
        "Federated room event ingestion is not available"
      )
    else
      ProtocolController.respond(conn, {:error, :invalid_param})
    end
  end
end
