defmodule LakehouseWeb.IamBackendController do
  use LakehouseWeb, :controller

  def create(conn, params) do
    case LakehouseIam.Federated.register(params) do
      {:ok, session_id, canonical_username} ->
        json(conn, %{
          sessionID: session_id,
          username: canonical_username
        })

      {:error, msg} when is_binary(msg) ->
        conn
        |> put_status(:bad_request)
        |> json(msg)
    end
  end
end
