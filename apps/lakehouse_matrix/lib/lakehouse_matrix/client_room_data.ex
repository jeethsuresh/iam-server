defmodule LakehouseMatrix.ClientRoomData do
  @moduledoc "Private room tags and membership-scoped mutual-room discovery."
  alias LakehouseIam.Repo
  alias LakehouseMatrix.{ClientStore, ClientSync, Cursor, Identity}
  alias LakehouseMatrix.Protocol.Event
  alias LakehouseMatrix.Federation.Transport

  def valid_room_ref?("!" <> rest = ref) when byte_size(ref) <= 255 do
    not Regex.match?(~r/[\x00-\x20\x7f]/, ref) and
      case String.split(rest, ":", parts: 2) do
        [opaque, server] when opaque != "" -> match?({:ok, _}, Transport.server_name(server))
        [_] -> Regex.match?(~r/\A[A-Za-z0-9_-]{43}\z/, rest)
        _ -> false
      end
  end

  def valid_room_ref?(_), do: false

  def tags(principal, ref) do
    if valid_room_ref?(ref),
      do: {:ok, %{"tags" => saved_tags(principal, ref)}},
      else: {:error, :invalid_param}
  end

  def tag(principal, ref, tag, method, content) do
    if valid_room_ref?(ref) and is_binary(tag) and byte_size(tag) in 1..255 and is_map(content) and
         byte_size(Jason.encode!(content)) <= 65_536 and valid_order?(content) and
         method in ["PUT", "DELETE"] do
      Repo.transaction(fn ->
        ClientStore.lock!()

        tags =
          if method == "PUT",
            do: Map.put(saved_tags(principal, ref), tag, content),
            else: Map.delete(saved_tags(principal, ref), tag)

        if byte_size(Jason.encode!(tags)) > 65_536, do: Repo.rollback(:limit_exceeded)
        {:ok, _} = ClientStore.put_data(principal, ref, "m.tag", %{"tags" => tags})
        %{}
      end)
    else
      {:error, :invalid_param}
    end
  end

  defp valid_order?(content),
    do:
      not Map.has_key?(content, "order") or
        (is_number(content["order"]) and content["order"] >= 0 and content["order"] <= 1)

  defp saved_tags(principal, ref) do
    tags = (ClientStore.get_data(principal, ref, "m.tag") || %{})["tags"]
    if is_map(tags), do: tags, else: %{}
  end

  def mutual(principal, device, params, batch_size \\ 100) when batch_size in 1..100 do
    user = params["user_id"]
    own = Repo.get!(LakehouseIam.Schema.Principal, principal).username |> Identity.user_id()

    with true <-
           is_binary(user) and byte_size(user) <= 255 and user != own and
             match?({:ok, _}, Event.user_domain(user)),
         {:ok, [high, after_ref]} <- mutual_cursor(params["from"], principal, device, user) do
      Repo.transaction(fn ->
        now = ClientStore.lock!()
        available = MapSet.new(ClientSync.memberships_at(principal, now).join)

        rooms =
          for id <- ClientSync.memberships_at(principal, high).join,
              MapSet.member?(available, id),
              joined?(id, user, high),
              joined?(id, user, now),
              do: Identity.room_id(id)

        rooms = Enum.sort(rooms)
        page = Enum.filter(rooms, &(&1 > after_ref)) |> Enum.take(batch_size + 1)
        chunk = Enum.take(page, batch_size)
        result = %{"joined" => chunk, "count" => length(rooms)}

        if length(page) > batch_size,
          do:
            Map.put(
              result,
              "next_batch",
              Cursor.encode("mutual", principal, device, [high, List.last(chunk)], user)
            ),
          else: result
      end)
    else
      false -> {:error, :invalid_param}
      error -> error
    end
  end

  defp joined?(room, user, high),
    do:
      Enum.any?(
        ClientSync.state_at(room, high),
        &(&1["type"] == "m.room.member" and &1["state_key"] == user and
            &1["content"]["membership"] == "join")
      )

  defp mutual_cursor(nil, _, _, _), do: {:ok, [ClientStore.position(), ""]}

  defp mutual_cursor(token, principal, device, user),
    do: Cursor.decode(token, "mutual", principal, device, user)
end
