defmodule LakehouseWeb.MatrixFixtures do
  @moduledoc false

  import Plug.Conn
  import Phoenix.ConnTest
  import Ecto.Query

  @endpoint LakehouseWeb.Endpoint

  alias LakehouseIam.{Accounts, IAM, Repo}
  alias LakehouseIam.Schema.{Permission, Role, RolePermission}

  def ensure_rbac! do
    for {name, desc} <- [
          {"member", "Default interactive user"},
          {"room_admin", "Room administration"}
        ] do
      unless Repo.get_by(Role, name: name) do
        %Role{} |> Role.changeset(%{name: name, description: desc}) |> Repo.insert!()
      end
    end

    for {name, desc} <- [
          {"matrix.room.join", "Join a room"},
          {"matrix.room.send", "Send timeline events"},
          {"matrix.room.create", "Create rooms"}
        ] do
      unless Repo.get_by(Permission, name: name) do
        %Permission{} |> Permission.changeset(%{name: name, description: desc}) |> Repo.insert!()
      end
    end

    member = Repo.get_by!(Role, name: "member")

    for perm_name <- ["matrix.room.join", "matrix.room.send", "matrix.room.create"] do
      perm = Repo.get_by!(Permission, name: perm_name)

      unless Repo.exists?(
               from rp in RolePermission,
                 where: rp.role_id == ^member.id and rp.permission_id == ^perm.id
             ) do
        %RolePermission{}
        |> RolePermission.changeset(%{role_id: member.id, permission_id: perm.id})
        |> Repo.insert!()
      end
    end

    :ok
  end

  def user_fixture(username \\ "alice") do
    ensure_rbac!()
    {:ok, principal} = Accounts.register_user(username, "password123", approve: true)
    _ = IAM.assign_role(principal.id, "member")
    principal
  end

  def matrix_login(conn, username \\ "alice", password \\ "password123") do
    conn
    |> put_req_header("content-type", "application/json")
    |> post("/_matrix/client/v3/login", %{
      "type" => "m.login.password",
      "identifier" => %{"type" => "m.id.user", "user" => username},
      "password" => password
    })
  end

  def auth_header(token) do
    {"authorization", "Bearer #{token}"}
  end
end
