defmodule LakehouseWeb.IamBackendController do
  use LakehouseWeb, :controller

  def create(conn, params) do
    username = params["username"]
    token_url = params["tokenURL"]
    redirect_url = params["redirectURL"]

    case LakehouseIam.Federated.register(username, token_url, redirect_url) do
      {:ok, session_id, canonical_username, public_key_b64} ->
        json(conn, %{
          sessionID: session_id,
          username: canonical_username,
          publicKey: public_key_b64
        })

      {:error, msg} when is_binary(msg) ->
        conn
        |> put_status(:bad_request)
        |> json(msg)
    end
  end
end
