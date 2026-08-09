import Ecto.Query

alias LakehouseIam.Repo
alias LakehouseIam.Schema.{Permission, Role, RolePermission}

for {name, desc} <- [
      {"member", "Default interactive user"},
      {"room_admin", "Room administration"}
    ] do
  unless Repo.exists?(from r in Role, where: r.name == ^name) do
    %Role{}
    |> Role.changeset(%{name: name, description: desc})
    |> Repo.insert!()
  end
end

for {name, desc} <- [
      {"matrix.room.join", "Join a room"},
      {"matrix.room.send", "Send timeline events"},
      {"matrix.room.create", "Create rooms"},
      {"calls.session.start", "Start WebRTC orchestration"}
    ] do
  unless Repo.exists?(from p in Permission, where: p.name == ^name) do
    %Permission{}
    |> Permission.changeset(%{name: name, description: desc})
    |> Repo.insert!()
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

IO.puts("Seeds complete.")
