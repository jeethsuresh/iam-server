defmodule LakehouseWeb.IamBackendController do
  use LakehouseWeb, :controller

  def create(conn, params) do
    case LakehouseIam.Federated.register(params) do
      {:ok, session_id, canonical_username} ->
        json(conn, %{
          sessionID: session_id,
          username: canonical_username,
          domain: LakehouseIam.Identifier.domain(),
          userID: if(canonical_username, do: LakehouseIam.Identifier.format(canonical_username)),
          authorizationURL:
            LakehouseIam.Discovery.public_url() <> "/oauth/authorize?sessionID=" <> session_id
        })

      {:error, msg} when is_binary(msg) ->
        conn
        |> put_status(:bad_request)
        |> json(msg)
    end
  end
end
