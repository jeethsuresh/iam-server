defmodule LakehouseWeb.Matrix.DeactivationTest do
  use LakehouseWeb.ConnCase, async: false
  alias LakehouseWeb.MatrixFixtures
  alias LakehouseMatrix.ClientLogin
  alias LakehouseIam.{Repo, Schema.Principal}

  setup do
    user = MatrixFixtures.user_fixture("deacthttp")
    {:ok, session} = ClientLogin.open(user, %{})
    %{user: user, session: session}
  end

  defp api(session, body) do
    build_conn()
    |> put_req_header("authorization", "Bearer " <> session["access_token"])
    |> post("/_matrix/client/v3/account/deactivate", body)
  end

  test "account closure uses standard UIA and invalidates the requesting token", c do
    challenge = api(c.session, %{"erase" => true}) |> json_response(401)
    assert challenge["flows"] == [%{"stages" => ["m.login.password"]}]

    auth = %{
      "type" => "m.login.password",
      "user" => c.user.username,
      "password" => "password123",
      "session" => challenge["session"]
    }

    assert api(c.session, %{"erase" => true, "auth" => auth}) |> json_response(200) == %{
             "id_server_unbind_result" => "success"
           }

    assert api(c.session, %{}) |> json_response(401) |> Map.fetch!("errcode") == "M_UNKNOWN_TOKEN"
    assert Repo.get!(Principal, c.user.id).matrix_deactivated
  end

  test "suspended accounts can close their account, while a lock retains the standard logout-only restriction",
       c do
    user = Repo.get!(Principal, c.user.id)
    user |> Ecto.Changeset.change(matrix_suspended: true) |> Repo.update!()
    assert api(c.session, %{}) |> json_response(401) |> Map.has_key?("flows")
    user |> Ecto.Changeset.change(matrix_locked: true, matrix_suspended: true) |> Repo.update!()
    assert api(c.session, %{}) |> json_response(401) |> Map.fetch!("errcode") == "M_USER_LOCKED"
    refute Repo.get!(Principal, c.user.id).matrix_deactivated
  end
end
