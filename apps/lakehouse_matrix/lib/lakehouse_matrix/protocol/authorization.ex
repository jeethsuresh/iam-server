defmodule LakehouseMatrix.Protocol.Authorization do
  @moduledoc "Room-version 11/12 event authorization, independent of River's local IAM policy."
  alias LakehouseMatrix.Protocol.Event
  alias LakehouseMatrix.Federation.Signing
  @versions ["11", "12"]
  @scalar_power ~w(users_default events_default state_default ban redact kick invite)

  def key(event), do: {event["type"], event["state_key"]}

  def auth_keys(%{"type" => "m.room.create"}, _version), do: []

  def auth_keys(event, version) do
    base = [{"m.room.power_levels", ""}, {"m.room.member", event["sender"]}]
    base = if version == "12", do: base, else: [{"m.room.create", ""} | base]

    base =
      if event["type"] == "m.room.member" do
        content = event["content"]
        keys = [{"m.room.member", event["state_key"]} | base]

        keys =
          if content["membership"] in ~w(join invite knock),
            do: [{"m.room.join_rules", ""} | keys],
            else: keys

        keys =
          if content["membership"] == "invite" and is_map(content["third_party_invite"]),
            do: [
              {"m.room.third_party_invite",
               get_in(content, ["third_party_invite", "signed", "token"])}
              | keys
            ],
            else: keys

        if content["membership"] == "join" and
             is_binary(content["join_authorised_via_users_server"]),
           do: [{"m.room.member", content["join_authorised_via_users_server"]} | keys],
           else: keys
      else
        base
      end

    Enum.uniq(base)
  end

  def select_auth(event, state, version) do
    for key <- auth_keys(event, version),
        auth = state[key],
        not is_nil(auth),
        do: auth["event_id"]
  end

  @doc "Check the declared auth graph before checking the state at the event."
  def check_auth_events(event, graph, version, create \\ nil) do
    refs = event["auth_events"] || []
    events = Enum.map(refs, &graph[&1])
    keys = Enum.map(events, fn e -> if is_map(e), do: key(e) end)
    allowed = auth_keys(event, version)

    cond do
      Enum.any?(events, &is_nil/1) ->
        {:error, :missing_auth_event}

      length(Enum.uniq(keys)) != length(keys) ->
        {:error, :duplicate_auth_event}

      Enum.any?(keys, &(&1 not in allowed)) ->
        {:error, :unexpected_auth_event}

      Enum.any?(events, &(&1[:auth_rejected] == true)) ->
        {:error, :rejected_auth_event}

      Enum.any?(events, &(&1["room_id"] != event["room_id"])) ->
        {:error, :wrong_auth_room}

      true ->
        state = Map.new(events, &{key(&1), &1})

        state =
          if version == "12" and create,
            do: Map.put(state, {"m.room.create", ""}, create),
            else: state

        check(event, state, version)
    end
  end

  @doc "Signatures and event format must be verified before calling this function."
  def check(event, state, version) when version in @versions and is_map(state) do
    cond do
      event["type"] == "m.room.create" ->
        check_create(event, version)

      not valid_create?(event, state, version) ->
        {:error, :wrong_create_event}

      not federates?(event, state) ->
        {:error, :non_federating_room}

      event["type"] == "m.room.member" ->
        check_member(event, state, version)

      membership(state, event["sender"]) != "join" ->
        {:error, :sender_not_joined}

      event["type"] == "m.room.third_party_invite" ->
        allow(gte?(power(state, event["sender"], version), level(state, "invite", 0)))

      not gte?(power(state, event["sender"], version), required_power(state, event)) ->
        {:error, :insufficient_power}

      is_binary(event["state_key"]) and String.starts_with?(event["state_key"], "@") and
          event["state_key"] != event["sender"] ->
        {:error, :wrong_state_key}

      event["type"] == "m.room.power_levels" ->
        check_power(event, state, version)

      true ->
        :ok
    end
  rescue
    _ -> {:error, :invalid_event}
  end

  def check(_, _, _), do: {:error, :unsupported_room_version}

  def creators(state) do
    create = state[{"m.room.create", ""}] || %{}
    [create["sender"] | get_in(create, ["content", "additional_creators"]) || []]
  end

  def power(state, user, version) do
    create = state[{"m.room.create", ""}]
    levels = content(state, "m.room.power_levels")

    cond do
      version == "12" and user in creators(state) -> :infinity
      is_map(levels) -> get_in(levels, ["users", user]) || levels["users_default"] || 0
      create && create["sender"] == user -> 100
      true -> 0
    end
  end

  def gte?(:infinity, _), do: true
  def gte?(_, :infinity), do: false
  def gte?(a, b) when is_integer(a) and is_integer(b), do: a >= b
  def gte?(_, _), do: false
  def greater?(a, b), do: gte?(a, b) and a != b

  def membership(state, user),
    do: get_in(state, [{"m.room.member", user}, "content", "membership"])

  def level(state, name, default),
    do: (content(state, "m.room.power_levels") || %{})[name] || default

  defp required_power(state, event) do
    power = content(state, "m.room.power_levels") || %{}

    get_in(power, ["events", event["type"]]) ||
      if(Map.has_key?(event, "state_key"),
        do: power["state_default"] || 50,
        else: power["events_default"] || 0
      )
  end

  defp check_create(event, version) do
    content = event["content"]

    valid =
      event["prev_events"] == [] and event["auth_events"] == [] and event["state_key"] == "" and
        content["room_version"] in [nil, version] and
        (version != "12" or
           (not Map.has_key?(event, "room_id") and
              (not Map.has_key?(content, "additional_creators") or
                 (is_list(content["additional_creators"]) and
                    Enum.all?(
                      content["additional_creators"],
                      &match?({:ok, _}, Event.user_domain(&1))
                    ))))) and
        (version != "11" or same_domain?(event["room_id"], event["sender"]))

    allow(valid)
  end

  defp valid_create?(event, state, version) do
    case state[{"m.room.create", ""}] do
      nil ->
        false

      %{auth_rejected: true} ->
        false

      create ->
        if version == "12",
          do: Event.room_id(create, version) == event["room_id"],
          else: create["room_id"] == event["room_id"]
    end
  end

  defp federates?(event, state) do
    create = state[{"m.room.create", ""}]

    get_in(create, ["content", "m.federate"]) != false or
      Event.user_domain(event["sender"]) == Event.user_domain(create["sender"])
  end

  defp check_member(event, state, version) do
    sender = event["sender"]
    target = event["state_key"]
    member = event["content"]["membership"]
    joined = membership(state, sender) == "join"
    prior = membership(state, target)
    sender_power = power(state, sender, version)
    target_power = power(state, target, version)
    rule = (content(state, "m.room.join_rules") || %{})["join_rule"] || "invite"
    create = state[{"m.room.create", ""}]

    cond do
      not match?({:ok, _}, Event.user_domain(target)) ->
        {:error, :invalid_member}

      member == "join" ->
        initial = target == create["sender"] and event["prev_events"] == [create["event_id"]]
        via = event["content"]["join_authorised_via_users_server"]

        permitted =
          case rule do
            "public" ->
              true

            r when r in ~w(invite knock) ->
              prior in ~w(invite join)

            r when r in ~w(restricted knock_restricted) ->
              prior in ~w(invite join) or
                (is_binary(via) and membership(state, via) == "join" and
                   gte?(power(state, via, version), level(state, "invite", 0)))

            _ ->
              false
          end

        allow(initial or (sender == target and prior != "ban" and permitted))

      member == "invite" and Map.has_key?(event["content"], "third_party_invite") ->
        allow(prior != "ban" and third_party_invite?(event, state))

      member == "invite" ->
        allow(
          joined and prior not in ~w(join ban) and gte?(sender_power, level(state, "invite", 0))
        )

      member == "leave" and sender == target ->
        allow(prior in ~w(invite join knock))

      member == "leave" ->
        allow(
          joined and gte?(sender_power, level(state, "kick", 50)) and
            (prior != "ban" or gte?(sender_power, level(state, "ban", 50))) and
            greater?(sender_power, target_power)
        )

      member == "ban" ->
        allow(
          joined and gte?(sender_power, level(state, "ban", 50)) and
            greater?(sender_power, target_power)
        )

      member == "knock" ->
        allow(
          rule in ~w(knock knock_restricted) and sender == target and
            membership(state, sender) not in ~w(ban invite join)
        )

      true ->
        {:error, :invalid_membership}
    end
  end

  defp third_party_invite?(event, state) do
    signed = get_in(event, ["content", "third_party_invite", "signed"])

    with true <- is_map(signed),
         token when is_binary(token) <- signed["token"],
         true <- signed["mxid"] == event["state_key"],
         invite when is_map(invite) <- state[{"m.room.third_party_invite", token}],
         true <- invite["sender"] == event["sender"] do
      content = invite["content"]
      keys = [content["public_key"] | Enum.map(content["public_keys"] || [], & &1["public_key"])]

      Enum.any?(keys, fn encoded ->
        with true <- is_binary(encoded),
             {:ok, public} <- Base.decode64(encoded, padding: false) do
          Enum.any?(signed["signatures"] || %{}, fn {server, ids} ->
            is_map(ids) and
              Enum.any?(ids, fn {id, _} ->
                String.starts_with?(id, "ed25519:") and Signing.verify(signed, public, id, server)
              end)
          end)
        else
          _ -> false
        end
      end)
    else
      _ -> false
    end
  end

  defp check_power(event, state, version) do
    new = event["content"]
    old = content(state, "m.room.power_levels")
    sender = event["sender"]
    power = power(state, sender, version)

    valid =
      Enum.all?(@scalar_power, &(not Map.has_key?(new, &1) or is_integer(new[&1]))) and
        Enum.all?(~w(users events notifications), fn k ->
          not Map.has_key?(new, k) or
            (is_map(new[k]) and
               Enum.all?(new[k], fn {user, level} ->
                 is_integer(level) and (k != "users" or match?({:ok, _}, Event.user_domain(user)))
               end))
        end) and
        (version != "12" or
           Enum.all?(creators(state), &(not Map.has_key?(new["users"] || %{}, &1))))

    cond do
      not valid ->
        {:error, :invalid_power_levels}

      is_nil(old) ->
        :ok

      true ->
        scalars =
          Enum.all?(@scalar_power, fn k ->
            old[k] == new[k] or (gte?(power, old[k] || 0) and gte?(power, new[k] || 0))
          end)

        maps =
          Enum.all?(~w(events notifications users), fn k ->
            before = old[k] || %{}
            after_values = new[k] || %{}

            Enum.all?(Enum.uniq(Map.keys(before) ++ Map.keys(after_values)), fn name ->
              before[name] == after_values[name] or
                ((is_nil(before[name]) or
                    if(k == "users" and name != sender,
                      do: greater?(power, before[name]),
                      else: gte?(power, before[name])
                    )) and
                   (is_nil(after_values[name]) or gte?(power, after_values[name])))
            end)
          end)

        allow(scalars and maps)
    end
  end

  defp same_domain?("!" <> room, user) do
    case String.split(room, ":", parts: 2) do
      [_, server] -> Event.user_domain(user) == {:ok, server}
      _ -> false
    end
  end

  defp same_domain?(_, _), do: false
  defp content(state, type), do: get_in(state, [{type, ""}, "content"])
  defp allow(true), do: :ok
  defp allow(_), do: {:error, :forbidden}
end
