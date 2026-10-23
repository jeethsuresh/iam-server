defmodule LakehouseWeb.AdminRoleTest do
  use LakehouseWeb.ConnCase

  alias LakehouseIam.{Accounts, Auth.Token, IAM}

  setup do
    LakehouseIam.Fixtures.ensure_rbac!()
    {:ok, actor} = Accounts.register_user("apiroleadmin", "password123", approve: true)
    {:ok, _} = Accounts.register_user("apirolepending", "password123", approve: false)
    {:ok, actor: actor, token: Token.issue(actor.username)}
  end

  test "existing sessions gain and lose admin access with the global grant", %{
    actor: actor,
    token: token
  } do
    assert approve(token) |> json_response(403)
    assert {:ok, _} = IAM.assign_role(actor.id, "admin")
    assert approve(token) |> json_response(200)
    assert {:ok, %{active: true}} = Accounts.fetch_user("apirolepending")

    assert :ok = IAM.revoke_role(actor.id, "admin")
    assert approve(token) |> json_response(403)
  end

  defp approve(token) do
    build_conn()
    |> put_req_header("authorization", "Bearer " <> token)
    |> post("/admin/approve", %{username: "apirolepending"})
  end
end
