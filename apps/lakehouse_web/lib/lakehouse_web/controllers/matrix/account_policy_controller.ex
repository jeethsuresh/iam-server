defmodule LakehouseWeb.Matrix.AccountPolicyController do
  use LakehouseWeb, :controller
  alias LakehouseWeb.Matrix.ProtocolController

  # IAM owns account approval and recovery. A Matrix flow must never create an
  # unapproved identity or claim that an IAM address is a Matrix 3PID binding.
  def registration(conn, _),
    do:
      matrix_error(
        conn,
        403,
        "M_FORBIDDEN",
        "Create an account through Gravitas account registration and approval"
      )

  def password(conn, _),
    do:
      matrix_error(
        conn,
        403,
        "M_FORBIDDEN",
        "Manage passwords and account recovery through Gravitas"
      )

  def threepids(%{method: "GET"} = conn, _), do: json(conn, %{"threepids" => []})

  def threepids(conn, _),
    do:
      matrix_error(
        conn,
        403,
        "M_THREEPID_DENIED",
        "Matrix third-party identifier changes are disabled"
      )

  def protocols(conn, _), do: json(conn, %{})
  def thirdparty(conn, _), do: ProtocolController.respond(conn, {:error, :not_found})

  def turn(conn, _) do
    conn = put_resp_header(conn, "cache-control", "no-store")
    ProtocolController.respond(conn, LakehouseMatrix.Turn.credentials(conn.assigns.username))
  end

  defp matrix_error(conn, status, code, message),
    do: conn |> put_status(status) |> json(%{"errcode" => code, "error" => message})
end
