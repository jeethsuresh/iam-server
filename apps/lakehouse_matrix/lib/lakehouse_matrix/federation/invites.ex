defmodule LakehouseMatrix.Federation.Invites do
  @moduledoc "Store verified remote invitations as outliers until a full room join is authenticated."
  import Ecto.Query
  alias LakehouseIam.{Accounts, Repo}
  alias LakehouseMatrix.{ClientStore, Events, Identity, Memberships, Rooms}
  alias LakehouseMatrix.Events.Context
  alias LakehouseMatrix.Federation.{Keyring, Signing}
  alias LakehouseMatrix.Protocol.{Event, Graph}
  alias LakehouseMatrix.Schema.{ProtocolRoom, RoomEvent}

  def receive(origin, ref, id, params, lookup \\ &Keyring.key/3) do
    version = params["room_version"]
    event = params["event"]
    stripped = params["invite_room_state"] || []

    with true <- version in Event.versions(),
         true <- is_map(event) and is_list(stripped) and length(stripped) <= 100,
         true <-
           event["room_id"] == ref and event["type"] == "m.room.member" and
             get_in(event, ["content", "membership"]) == "invite",
         {:ok, ^origin} <- Event.user_domain(event["sender"]),
         {:ok, local} <- Identity.parse_user_id(event["state_key"]),
         {:ok, target} <- Accounts.fetch_user(local),
         true <- target.active,
         :ok <- Event.verify_sender(event, version, lookup),
         {:ok, verified} <- Event.verify(event, version, lookup),
         true <- verified["event_id"] == id,
         {:ok, seed, key} <- Signing.config() do
      signed =
        Event.add_signature(
          Map.delete(verified, "event_id"),
          version,
          seed,
          key,
          Identity.homeserver_domain()
        )

      Repo.transaction(fn ->
        ClientStore.lock!()
        metadata = metadata!(ref, version, stripped)

        if metadata.extremities != [] do
          case Graph.receive_pdu(metadata.local_room_id, signed, lookup) do
            {:ok, _} -> :ok
            {:error, reason} -> Repo.rollback(reason)
          end
        else
          Repo.insert_all(
            "matrix_pdus",
            [
              %{
                event_id: id,
                local_room_id: ClientStore.dump_id(metadata.local_room_id),
                pdu: signed,
                outlier: true,
                received_at: ClientStore.now()
              }
            ],
            on_conflict: :nothing,
            conflict_target: [:event_id]
          )

          unless Repo.exists?(from e in RoomEvent, where: e.event_id == ^id) do
            ctx = %Context{
              room_id: metadata.local_room_id,
              event_id: id,
              type: "m.room.member",
              sender: signed["sender"],
              state_key: signed["state_key"],
              content: signed["content"],
              origin_server_ts: signed["origin_server_ts"]
            }

            {:ok, _} = Events.persist(ctx, %{"content" => signed["content"]})
            # Publish only the authenticated recipient's invitation into the
            # client membership stream. Unverified stripped room state remains
            # outside the protocol graph's resolved authorization state.
            Repo.insert_all("matrix_state_changes", [
              %{
                local_room_id: ClientStore.dump_id(metadata.local_room_id),
                type: "m.room.member",
                state_key: signed["state_key"],
                event_id: id
              }
            ])

            {:ok, _} =
              Memberships.upsert_membership(metadata.local_room_id, target.id, "invite", ctx)
          end

          own = Map.take(signed, ~w(type state_key sender content))

          stripped =
            Enum.filter(stripped, fn e ->
              is_map(e) and is_binary(e["type"]) and is_binary(e["state_key"]) and
                is_map(e["content"])
            end)
            |> Enum.map(&Map.take(&1, ~w(type state_key sender content)))
            |> Enum.reject(
              &(&1["type"] == "m.room.member" and &1["state_key"] == signed["state_key"])
            )

          Repo.insert_all(
            "matrix_pending_invites",
            [
              %{
                local_room_id: ClientStore.dump_id(metadata.local_room_id),
                user_id: signed["state_key"],
                origin: origin,
                event_id: id,
                stripped_state: %{"events" => stripped ++ [own]}
              }
            ],
            on_conflict: [
              set: [
                origin: origin,
                event_id: id,
                stripped_state: %{"events" => stripped ++ [own]}
              ]
            ],
            conflict_target: [:local_room_id, :user_id]
          )
        end

        %{"event" => signed}
      end)
    else
      {:error, _} = error -> error
      _ -> {:error, :forbidden}
    end
  end

  def pending(local_id, user) do
    Repo.one(
      from i in "matrix_pending_invites",
        where: i.local_room_id == type(^local_id, :binary_id) and i.user_id == ^user,
        select: %{origin: i.origin, event_id: i.event_id, state: i.stripped_state}
    )
  end

  defp metadata!(ref, version, stripped) do
    case Graph.room_by_id(ref) do
      nil ->
        name =
          Enum.find_value(stripped, "Invitation", fn
            %{"type" => "m.room.name", "content" => %{"name" => name}}
            when is_binary(name) and name != "" ->
              name

            _ ->
              nil
          end)

        {:ok, room} = Rooms.create_room_record(%{name: name})
        create = if version == "12", do: String.replace_prefix(ref, "!", "$"), else: ""

        Repo.insert!(%ProtocolRoom{
          local_room_id: room.id,
          room_id: ref,
          version: version,
          create_id: create
        })

      metadata ->
        if metadata.version != version, do: Repo.rollback(:unsupported_room_version)
        metadata
    end
  end
end
