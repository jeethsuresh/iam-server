defmodule LakehouseMatrix.PushRules do
  @moduledoc "Matrix 1.19 default and user push rules, ordered mutations and condition evaluation."
  alias LakehouseIam.Repo
  alias LakehouseMatrix.{ClientStore, Identity}
  alias LakehouseMatrix.Protocol.Authorization
  @kinds ~w(override content room sender underride)
  @external_resource Path.expand("../../priv/matrix-1.19-push-rules.json", __DIR__)
  @defaults @external_resource |> File.read!() |> Jason.decode!()

  def defaults(user), do: substitute(@defaults, user)

  def get(principal) do
    user = Repo.get!(LakehouseIam.Schema.Principal, principal).username |> Identity.user_id()
    stored = ClientStore.get_data(principal, "", "m.push_rules") || %{}
    base = defaults(user)

    global =
      Map.new(@kinds, fn kind ->
        saved = saved_rules(stored, kind)
        users = Enum.filter(saved, &(&1["default"] == false))

        servers =
          Enum.map(base[kind], fn rule ->
            override = Enum.find(saved, &(&1["rule_id"] == rule["rule_id"])) || %{}
            Map.merge(rule, Map.take(override, ~w(enabled actions)))
          end)

        ordered =
          if kind == "override", do: [hd(servers)] ++ users ++ tl(servers), else: users ++ servers

        {kind, ordered}
      end)

    %{"global" => global}
  end

  def fetch(principal, kind, id, field \\ nil) do
    with true <- kind in @kinds,
         rule when is_map(rule) <-
           Enum.find(get(principal)["global"][kind], &(&1["rule_id"] == id)),
         true <- field in [nil, "enabled", "actions"] do
      {:ok, if(field, do: %{field => rule[field]}, else: rule)}
    else
      _ -> {:error, :not_found}
    end
  end

  def mutate(principal, kind, id, method, params, field \\ nil) do
    if kind in @kinds and is_binary(id) and byte_size(id) in 1..255 and
         not String.contains?(id, ["/", "\\"]) and field in [nil, "enabled", "actions"] and
         byte_size(Jason.encode!(params)) <= 65_536 do
      Repo.transaction(fn ->
        ClientStore.lock!()
        all = get(principal)
        rules = all["global"][kind]
        existing = Enum.find(rules, &(&1["rule_id"] == id))
        rules = change(rules, existing, kind, id, method, params, field)
        global = Map.put(all["global"], kind, rules)

        if Enum.sum(Enum.map(global, fn {_, rows} -> length(rows) end)) > 1000 or
             byte_size(Jason.encode!(global)) > 262_144,
           do: Repo.rollback(:limit_exceeded)

        {:ok, _} = ClientStore.put_data(principal, "", "m.push_rules", %{"global" => global})
        %{}
      end)
    else
      {:error, :invalid_param}
    end
  end

  defp change(rules, rule, _, id, "DELETE", _, nil) do
    unless rule, do: Repo.rollback(:not_found)
    if rule["default"], do: Repo.rollback(:invalid_param)
    Enum.reject(rules, &(&1["rule_id"] == id))
  end

  defp change(rules, rule, _, id, "PUT", params, field) when field in ["enabled", "actions"] do
    unless rule, do: Repo.rollback(:not_found)

    unless (field == "enabled" and is_boolean(params[field])) or
             (field == "actions" and valid_actions?(params[field])),
           do: Repo.rollback(:invalid_param)

    Enum.map(rules, fn r ->
      if r["rule_id"] == id, do: Map.put(r, field, clean(params[field])), else: r
    end)
  end

  defp change(rules, existing, kind, id, "PUT", params, nil) do
    if String.starts_with?(id, "."), do: Repo.rollback(:invalid_param)

    unless valid_actions?(params["actions"]) and
             (kind != "content" or
                (is_binary(params["pattern"]) and byte_size(params["pattern"]) <= 4096)) and
             (kind not in ["override", "underride"] or
                valid_conditions?(params["conditions"] || [])),
           do: Repo.rollback(:invalid_param)

    rule = %{
      "rule_id" => id,
      "default" => false,
      "enabled" => if(existing, do: existing["enabled"], else: true),
      "actions" => clean(params["actions"])
    }

    rule =
      cond do
        kind == "content" ->
          Map.put(rule, "pattern", params["pattern"])

        kind in ["override", "underride"] ->
          Map.put(rule, "conditions", params["conditions"] || [])

        true ->
          rule
      end

    users = Enum.filter(rules, &(&1["default"] == false and &1["rule_id"] != id))
    before = params["before"]
    after_id = params["after"]

    old_position =
      Enum.find_index(Enum.filter(rules, &(&1["default"] == false)), &(&1["rule_id"] == id))

    before_at = if before, do: Enum.find_index(users, &(&1["rule_id"] == before))
    after_at = if after_id, do: Enum.find_index(users, &(&1["rule_id"] == after_id))

    if (not is_nil(before) and is_nil(before_at)) or (not is_nil(after_id) and is_nil(after_at)) or
         (not is_nil(before_at) and not is_nil(after_at) and after_at >= before_at),
       do: Repo.rollback(:invalid_param)

    position =
      cond do
        not is_nil(before_at) -> before_at
        not is_nil(after_at) -> after_at + 1
        true -> old_position || 0
      end

    users = List.insert_at(users, position, rule)
    defaults = Enum.filter(rules, &(&1["default"] == true))
    if kind == "override", do: [hd(defaults)] ++ users ++ tl(defaults), else: users ++ defaults
  end

  defp change(_, _, _, _, _, _, _), do: Repo.rollback(:invalid_param)

  def evaluate(rules, event, context) do
    Enum.find_value(@kinds, [], fn kind ->
      case Enum.find(
             rules["global"][kind] || [],
             &(&1["enabled"] == true and matches?(&1, kind, event, context))
           ) do
        nil -> nil
        rule -> {:matched, clean(rule["actions"])}
      end
    end)
    |> then(fn
      {:matched, actions} -> actions
      [] -> []
    end)
  end

  defp matches?(rule, "content", e, _),
    do: glob?(get_in(e, ["content", "body"]), rule["pattern"], true)

  defp matches?(rule, "room", e, _), do: e["room_id"] == rule["rule_id"]
  defp matches?(rule, "sender", e, _), do: e["sender"] == rule["rule_id"]

  defp matches?(rule, _, e, context),
    do: Enum.all?(rule["conditions"] || [], &condition?(&1, e, context))

  def condition?(%{"kind" => "event_match", "key" => key, "pattern" => pattern}, event, _),
    do: glob?(property(event, key), pattern, key == "content.body")

  def condition?(%{"kind" => "event_property_is", "key" => key, "value" => value}, event, _),
    do: scalar?(value) and property(event, key) !== :missing and property(event, key) === value

  def condition?(%{"kind" => "event_property_contains", "key" => key, "value" => value}, event, _) do
    found = property(event, key)
    scalar?(value) and is_list(found) and Enum.any?(found, &(&1 === value))
  end

  def condition?(%{"kind" => "contains_display_name"}, event, context),
    do:
      is_binary(context[:displayname]) and context[:displayname] != "" and
        glob?(get_in(event, ["content", "body"]), escape_glob(context[:displayname]), true)

  def condition?(%{"kind" => "room_member_count", "is" => comparison}, _, context)
      when is_binary(comparison) do
    case if(byte_size(comparison) <= 20,
           do: Regex.run(~r/\A(==|<=|>=|<|>)?([0-9]+)\z/, comparison)
         ) do
      [_, op, number] -> compare(context[:members] || 0, String.to_integer(number), op)
      _ -> false
    end
  end

  def condition?(%{"kind" => "sender_notification_permission", "key" => key}, event, context)
      when is_binary(key) do
    state = context[:state] || %{}
    required = get_in(state, [{"m.room.power_levels", ""}, "content", "notifications", key]) || 50

    Authorization.gte?(
      Authorization.power(state, event["sender"], context[:version] || "11"),
      required
    )
  end

  def condition?(_, _, _), do: false

  def property(event, key) when is_binary(key) do
    path = path(String.graphemes(key), [], [])

    Enum.reduce(path, event, fn part, value ->
      if is_map(value), do: Map.get(value, part, :missing), else: :missing
    end)
  end

  def property(_, _), do: :missing
  defp path([], part, result), do: Enum.reverse([Enum.reverse(part) |> Enum.join() | result])
  defp path(["\\", c | rest], part, result), do: path(rest, [c | part], result)

  defp path(["." | rest], part, result),
    do: path(rest, [], [Enum.reverse(part) |> Enum.join() | result])

  defp path([c | rest], part, result), do: path(rest, [c | part], result)

  def glob?(value, pattern, word? \\ false)

  def glob?(value, pattern, word?)
      when is_binary(value) and is_binary(pattern) and byte_size(pattern) <= 4096 do
    expression = glob(String.graphemes(pattern)) |> Enum.join()

    expression =
      if word?,
        do: "(?:\\A|[^A-Za-z0-9_])(?:" <> expression <> ")(?=\\z|[^A-Za-z0-9_])",
        else: "\\A(?:" <> expression <> ")\\z"

    case :re.compile(expression, [:unicode, :caseless, :dotall]) do
      {:ok, regex} ->
        :re.run(value, regex, capture: :none, match_limit: 100_000, match_limit_recursion: 1000) ==
          :match

      _ ->
        false
    end
  end

  def glob?(_, _, _), do: false
  defp glob([]), do: []
  defp glob(["\\", c | rest]), do: [Regex.escape(c) | glob(rest)]
  defp glob(["*" | rest]), do: [".*" | glob(rest)]
  defp glob(["?" | rest]), do: ["." | glob(rest)]
  defp glob([c | rest]), do: [Regex.escape(c) | glob(rest)]

  defp escape_glob(value),
    do:
      value
      |> String.replace("\\", "\\\\")
      |> String.replace("*", "\\*")
      |> String.replace("?", "\\?")

  defp compare(a, b, op) when op in ["", "=="], do: a == b
  defp compare(a, b, "<"), do: a < b
  defp compare(a, b, ">"), do: a > b
  defp compare(a, b, "<="), do: a <= b
  defp compare(a, b, ">="), do: a >= b

  defp scalar?(v),
    do:
      is_nil(v) or is_boolean(v) or is_binary(v) or
        (is_integer(v) and v in -9_007_199_254_740_991..9_007_199_254_740_991)

  defp valid_actions?(actions),
    do:
      is_list(actions) and length(actions) <= 100 and
        Enum.all?(actions, &(is_binary(&1) or is_map(&1)))

  defp valid_conditions?(conditions),
    do:
      is_list(conditions) and length(conditions) <= 100 and
        Enum.all?(conditions, &valid_condition?/1)

  defp valid_condition?(%{"kind" => kind} = condition) when is_binary(kind) do
    key? = is_binary(condition["key"]) and byte_size(condition["key"]) in 1..255

    case kind do
      "event_match" ->
        key? and is_binary(condition["pattern"]) and byte_size(condition["pattern"]) <= 4096

      kind when kind in ["event_property_is", "event_property_contains"] ->
        key? and Map.has_key?(condition, "value") and scalar?(condition["value"])

      "sender_notification_permission" ->
        key?

      "room_member_count" ->
        is_binary(condition["is"]) and byte_size(condition["is"]) <= 20 and
          Regex.match?(~r/\A(==|<=|>=|<|>)?[0-9]+\z/, condition["is"])

      _ ->
        true
    end
  end

  defp valid_condition?(_), do: false

  defp clean(actions) when is_list(actions),
    do: Enum.reject(actions, &(&1 in ["dont_notify", "coalesce"]))

  defp clean(value), do: value
  defp substitute("[the user's Matrix ID]", user), do: user

  defp substitute(value, user) when is_map(value),
    do:
      Map.new(value, fn
        {"pattern", "[the user's Matrix ID]"} -> {"pattern", escape_glob(user)}
        {k, v} -> {k, substitute(v, user)}
      end)

  defp substitute(value, user) when is_list(value), do: Enum.map(value, &substitute(&1, user))
  defp substitute(value, _), do: value

  defp saved_rules(stored, kind) do
    global = stored["global"]
    rules = if is_map(global), do: global[kind]

    if is_list(rules),
      do:
        Enum.filter(rules, fn rule ->
          is_map(rule) and is_binary(rule["rule_id"]) and is_boolean(rule["enabled"]) and
            valid_actions?(rule["actions"]) and valid_conditions?(rule["conditions"] || []) and
            (kind != "content" or is_binary(rule["pattern"]))
        end),
      else: []
  end
end
