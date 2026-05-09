defmodule LakehouseWeb.IamRegistrationController do
  use LakehouseWeb, :controller

  alias LakehouseWeb.IamAuth

  def create(conn, params) do
    case IamAuth.register(params["username"], params["password"]) do
      {:ok, principal} ->
        msg =
          if principal.active do
            "User registered successfully. Your account is active."
          else
            "Registration received. An administrator must approve your account before you can sign in."
          end

        json(conn, %{message: msg})

      {:error, _st, body} ->
        conn
        |> put_status(:bad_request)
        |> json(body)
    end
  end
end
