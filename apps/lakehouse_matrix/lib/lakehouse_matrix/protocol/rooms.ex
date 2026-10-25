defmodule LakehouseMatrix.Protocol.Rooms do
  @moduledoc "Native Matrix room creation and local membership operations over signed PDUs."
  alias LakehouseIam.{Accounts, IAM, Repo}
  alias LakehouseMatrix.{ClientStore, Identity, Rooms}
  alias LakehouseMatrix.Protocol.{Graph, Event}

  def enabled?, do: Application.get_env(:lakehouse_matrix, :native_event_graph, false)

  def create(principal_id, params) do
    LakehouseMatrix.Protocol.Policy.transaction(fn ->
      ClientStore.lock!()
      unless IAM.can?(principal_id, "matrix.room.create", nil), do: Repo.rollback(:forbidden)
      principal = Repo.get!(LakehouseIam.Schema.Principal, principal_id)
      sender = Identity.user_id(principal.username)
      version = params["room_version"] || "12"
      unless version in Event.versions(), do: Repo.rollback(:unsupported_room_version)
      preset = params["preset"] || "private_chat"

      unless preset in ~w(private_chat trusted_private_chat public_chat),
        do: Repo.rollback(:invalid_param)

      initial = params["initial_state"] || []
      invites = params["invite"] || []
      creation = params["creation_content"] || %{}
      override = params["power_level_content_override"] || %{}

      unless is_list(initial) and length(initial) <= 100 and is_list(invites) and
               length(invites) <= 100 and
               is_map(creation) and is_map(override),
             do: Repo.rollback(:invalid_param)

      name = params["name"] || params["room_alias_name"] || "Room"
      visibility = params["visibility"] || "private"
      alias_name = params["room_alias_name"]

      unless visibility in ["private", "public"] and
               (is_nil(alias_name) or
                  (is_binary(alias_name) and
                     match?(
                       {:ok, _, _},
                       LakehouseMatrix.Directory.parse(Identity.room_alias(alias_name))
                     ))),
             do: Repo.rollback(:invalid_param)

      unless is_binary(name) and is_binary(params["topic"] || ""),
        do: Repo.rollback(:invalid_param)

      room =
        case Rooms.create_room_record(%{
               name: name,
               topic: params["topic"],
               alias: alias_name,
               visibility: visibility
             }) do
          {:ok, room} -> room
          _ -> Repo.rollback(:invalid_param)
        end

      require_ok!(Graph.create(room.id, sender, version, creation))

      if alias_name,
        do: require_ok!(LakehouseMatrix.Directory.register(principal_id, room.id, alias_name))

      require_ok!(
        Graph.send(
          room.id,
          sender,
          "m.room.member",
          %{"membership" => "join", "displayname" => principal.username},
          sender
        )
      )

      users = if version == "12", do: %{}, else: %{sender => 100}

      users =
        if preset == "trusted_private_chat",
          do: Enum.reduce(invites, users, &Map.put(&2, &1, 100)),
          else: users

      levels = %{
        "users" => users,
        "users_default" => 0,
        "events_default" => 0,
        "state_default" => 50,
        "invite" => 0,
        "kick" => 50,
        "ban" => 50,
        "redact" => 50
      }

      levels = Map.merge(levels, override)

      defaults = [
        {"m.room.power_levels", "", levels},
        {"m.room.join_rules", "",
         %{"join_rule" => if(preset == "public_chat", do: "public", else: "invite")}},
        {"m.room.history_visibility", "", %{"history_visibility" => "shared"}},
        {"m.room.guest_access", "", %{"guest_access" => "forbidden"}}
      ]

      state =
        Enum.reduce(initial, Map.new(defaults, fn {t, k, c} -> {{t, k}, c} end), fn event, acc ->
          unless is_map(event) and is_binary(event["type"]) and
                   is_binary(event["state_key"] || "") and
                   is_map(event["content"]) and
                   event["type"] not in ~w(m.room.create m.room.member),
                 do: Repo.rollback(:invalid_param)

          Map.put(acc, {event["type"], event["state_key"] || ""}, event["content"])
        end)

      for {{type, key}, content} <- Enum.sort(state),
          do: require_ok!(Graph.send(room.id, sender, type, content, key))

      if params["name"],
        do: require_ok!(Graph.send(room.id, sender, "m.room.name", %{"name" => name}, ""))

      if params["topic"],
        do:
          require_ok!(
            Graph.send(room.id, sender, "m.room.topic", %{"topic" => params["topic"]}, "")
          )

      if params["room_alias_name"],
        do:
          require_ok!(
            Graph.send(
              room.id,
              sender,
              "m.room.canonical_alias",
              %{"alias" => Identity.room_alias(params["room_alias_name"])},
              ""
            )
          )

      for user <- invites, do: require_ok!(invite(principal_id, room.id, user))
      %{"room_id" => Identity.room_id(room.id)}
    end)
  end

  def membership(principal, local_id, membership, content \\ %{}) do
    user = Repo.get!(LakehouseIam.Schema.Principal, principal).username |> Identity.user_id()

    LakehouseMatrix.Protocol.Policy.transaction(fn ->
      ClientStore.lock!()

      if membership == "join" and
           not IAM.can?(principal, "matrix.room.join", Identity.resource_arn(local_id)),
         do: Repo.rollback(:forbidden)

      metadata = Graph.room(local_id) || Repo.rollback(:room_not_found)

      template = %{
        "type" => "m.room.member",
        "sender" => user,
        "state_key" => user,
        "content" => Map.put(content, "membership", membership)
      }

      template =
        if membership == "join" do
          case LakehouseMatrix.Federation.RoomAccess.restricted_join(metadata, user, template) do
            {:ok, template} -> template
            {:error, reason} -> Repo.rollback(reason)
          end
        else
          template
        end

      require_ok!(Graph.send(local_id, user, "m.room.member", template["content"], user))
    end)
  end

  def invite(principal, local_id, user) do
    with {:ok, _} <- Event.user_domain(user), :ok <- local_target(user) do
      sender = Repo.get!(LakehouseIam.Schema.Principal, principal).username |> Identity.user_id()
      Graph.send(local_id, sender, "m.room.member", %{"membership" => "invite"}, user)
    else
      {:error, _} = error -> error
      _ -> {:error, :invalid_param}
    end
  end

  defp local_target(user) do
    case Identity.parse_user_id(user) do
      {:ok, name} ->
        case Accounts.fetch_user(name) do
          {:ok, p} -> if p.active, do: :ok, else: {:error, :not_found}
          _ -> {:error, :not_found}
        end

      _ ->
        :ok
    end
  end

  defp require_ok!({:ok, value}), do: value
  defp require_ok!({:error, reason}), do: Repo.rollback(reason)
end
