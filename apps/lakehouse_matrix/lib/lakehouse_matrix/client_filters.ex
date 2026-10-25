defmodule LakehouseMatrix.ClientFilters do
  @moduledoc "Shared Matrix event filters, applied in SQL before timeline limits."
  import Ecto.Query
  alias LakehouseMatrix.Identity

  def validate(filter) when is_map(filter) do
    room = if is_nil(filter["room"]), do: %{}, else: filter["room"]

    valid =
      is_map(room) and room["include_leave"] in [nil, true, false] and
        filter["event_format"] in [nil, "client", "federation"] and
        strings?(filter["event_fields"], 100) and
        strings?(room["rooms"]) and strings?(room["not_rooms"]) and
        Enum.all?(
          ~w(presence account_data),
          &valid_event?(if(is_nil(filter[&1]), do: %{}, else: filter[&1]))
        ) and
        Enum.all?(
          ~w(timeline state ephemeral account_data),
          &valid_event?(if(is_nil(room[&1]), do: %{}, else: room[&1]))
        )

    if valid, do: {:ok, filter}, else: {:error, :invalid_param}
  end

  def validate(_), do: {:error, :invalid_param}

  def include_room?(ref, filter) do
    (is_nil(filter["rooms"]) or ref in filter["rooms"]) and ref not in (filter["not_rooms"] || [])
  end

  def rooms(ids, filter), do: Enum.filter(ids, &include_room?(Identity.room_id(&1), filter))

  def events(events, filter, room \\ nil) do
    if is_binary(room) and not include_room?(room, filter) do
      []
    else
      matching =
        Enum.filter(events, fn event ->
          (is_nil(filter["types"]) or Enum.any?(filter["types"], &match_type?(event["type"], &1))) and
            not Enum.any?(filter["not_types"] || [], &match_type?(event["type"], &1)) and
            (is_nil(filter["senders"]) or event["sender"] in filter["senders"]) and
            event["sender"] not in (filter["not_senders"] || []) and
            (is_nil(filter["contains_url"]) or
               Map.has_key?(event["content"] || %{}, "url") == filter["contains_url"])
        end)

      if is_integer(filter["limit"]),
        do: Enum.take(matching, min(filter["limit"], 1000)),
        else: matching
    end
  end

  def render(events, "federation") do
    Enum.map(events, fn event ->
      case event["event_id"] && LakehouseMatrix.Protocol.Graph.event(event["event_id"]) do
        nil -> event
        record -> record.pdu
      end
    end)
  end

  def render(events, _), do: events

  def event_filter(nil), do: {:ok, %{}}

  def event_filter(value) when is_binary(value) and byte_size(value) <= 65_536 do
    with {:ok, filter} <- Jason.decode(value),
         true <- is_map(filter) and valid_event?(filter),
         do: {:ok, filter},
         else: (_ -> {:error, :invalid_param})
  end

  def event_filter(_), do: {:error, :invalid_param}

  def sql(query, filter) do
    query =
      if is_list(filter["types"]),
        do: from(e in query, where: ^type_condition(filter["types"])),
        else: query

    query =
      if filter["not_types"] in [nil, []],
        do: query,
        else: from(e in query, where: not (^type_condition(filter["not_types"])))

    query =
      if is_list(filter["senders"]),
        do: from(e in query, where: e.sender in ^filter["senders"]),
        else: query

    query =
      if filter["not_senders"] in [nil, []],
        do: query,
        else: from(e in query, where: e.sender not in ^filter["not_senders"])

    query =
      if is_boolean(filter["contains_url"]),
        do:
          from(e in query,
            where: fragment("jsonb_exists(?, 'url')", e.content) == ^filter["contains_url"]
          ),
        else: query

    query =
      if is_list(filter["rooms"]),
        do: from(e in query, where: e.room_id in ^local_ids(filter["rooms"])),
        else: query

    if filter["not_rooms"] in [nil, []],
      do: query,
      else: from(e in query, where: e.room_id not in ^local_ids(filter["not_rooms"]))
  end

  defp type_condition(types) do
    Enum.reduce(types, dynamic(false), fn type, condition ->
      pattern =
        type
        |> String.replace("\\", "\\\\")
        |> String.replace("%", "\\%")
        |> String.replace("_", "\\_")
        |> String.replace("*", "%")

      dynamic([e], ^condition or fragment("? LIKE ?", e.type, ^pattern))
    end)
  end

  defp local_ids(refs), do: for(ref <- refs, {:ok, id} <- [Identity.parse_room_id(ref)], do: id)

  defp match_type?(type, pattern) when is_binary(type) do
    expression = pattern |> Regex.escape() |> String.replace("\\*", ".*")
    Regex.match?(Regex.compile!("\\A" <> expression <> "\\z", "us"), type)
  end

  defp match_type?(_, _), do: false

  defp valid_event?(filter) when is_map(filter) do
    (is_nil(filter["limit"]) or (is_integer(filter["limit"]) and filter["limit"] >= 0)) and
      Enum.all?(~w(types not_types senders not_senders rooms not_rooms), &strings?(filter[&1])) and
      Enum.all?(
        ~w(contains_url lazy_load_members include_redundant_members unread_thread_notifications),
        &(filter[&1] in [nil, true, false])
      )
  end

  defp valid_event?(_), do: false
  defp strings?(value, count \\ 1000)
  defp strings?(nil, _), do: true

  defp strings?(value, count),
    do:
      is_list(value) and length(value) <= count and
        Enum.all?(value, &(is_binary(&1) and String.valid?(&1) and byte_size(&1) <= 1024))
end
