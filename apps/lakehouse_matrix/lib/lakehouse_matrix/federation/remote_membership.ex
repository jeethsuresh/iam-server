defmodule LakehouseMatrix.Federation.RemoteMembership do
  @moduledoc "Decline a remote invitation without promoting its unverified room state."
  alias LakehouseIam.Repo
  alias LakehouseMatrix.{ClientStore, Events, Identity, Memberships}
  alias LakehouseMatrix.Events.Context
  alias LakehouseMatrix.Federation.{Invites, Signing, Transport}
  alias LakehouseMatrix.Protocol.{Event, Graph}
  import Ecto.Query

  def reject_invite(principal, local, params \\ %{}, request \\ &Transport.request/4) do
    metadata = Graph.room(local)
    user = Repo.get!(LakehouseIam.Schema.Principal, principal).username |> Identity.user_id()

    with pending when not is_nil(pending) <- Invites.pending(local, user),
         true <-
           is_nil(params["reason"]) or
             (is_binary(params["reason"]) and byte_size(params["reason"]) <= 16_384),
         path <-
           "/_matrix/federation/v1/make_leave/" <> escape(metadata.room_id) <> "/" <> escape(user),
         {:ok, response} <- request.(:get, pending.origin, path, nil),
         template when is_map(template) <- response["event"],
         true <- is_map(template["content"]),
         true <-
           response["room_version"] in [nil, metadata.version] and
             template["room_id"] == metadata.room_id and template["sender"] == user and
             template["state_key"] == user and template["type"] == "m.room.member" and
             get_in(template, ["content", "membership"]) == "leave",
         {:ok, seed, key} <- Signing.config(),
         template <- Map.put(template, "origin_server_ts", System.system_time(:millisecond)),
         content <-
           Map.put(template["content"], "reason", params["reason"])
           |> Map.reject(fn {_, v} -> is_nil(v) end),
         event <-
           Event.sign(
             Map.put(template, "content", content),
             metadata.version,
             seed,
             key,
             Identity.homeserver_domain()
           ),
         :ok <- Event.validate(event, metadata.version) do
      Repo.transaction(fn ->
        ClientStore.lock!()
        LakehouseMatrix.AccountModeration.require!(principal, :read)
        current = Invites.pending(local, user)

        unless current && current.event_id == pending.event_id,
          do: Repo.rollback(:transaction_conflict)

        id = Event.id(event, metadata.version)

        Repo.insert_all(
          "matrix_pdus",
          [
            %{
              event_id: id,
              local_room_id: ClientStore.dump_id(local),
              pdu: event,
              outlier: true,
              received_at: ClientStore.now()
            }
          ],
          on_conflict: :nothing
        )

        ctx = %Context{
          room_id: local,
          event_id: id,
          type: "m.room.member",
          state_key: user,
          sender: user,
          principal_id: principal,
          content: content,
          origin_server_ts: event["origin_server_ts"]
        }

        {:ok, _} = Events.persist(ctx, %{"content" => content})
        {:ok, _} = Memberships.upsert_membership(local, principal, "leave", ctx)

        Repo.insert_all("matrix_state_changes", [
          %{
            local_room_id: ClientStore.dump_id(local),
            type: "m.room.member",
            state_key: user,
            event_id: id
          }
        ])

        Repo.delete_all(
          from i in "matrix_pending_invites",
            where: i.local_room_id == type(^local, :binary_id) and i.user_id == ^user
        )

        Repo.insert_all("matrix_federation_outbox", [
          %{
            destination: pending.origin,
            event_id: id,
            kind: "leave",
            payload: event,
            attempts: 0,
            available_at: ClientStore.now(),
            transaction_id: ClientStore.random()
          }
        ])

        %{}
      end)
    else
      {:error, _} -> {:error, :unavailable}
      _ -> {:error, :invalid_param}
    end
  rescue
    _ -> {:error, :unavailable}
  end

  def knock(principal, ref, servers, params, request \\ &Transport.request/4) do
    user = Repo.get!(LakehouseIam.Schema.Principal, principal).username |> Identity.user_id()

    peers =
      servers
      |> Enum.filter(
        &(is_binary(&1) and &1 != Identity.homeserver_domain() and
            match?({:ok, _}, Transport.server_name(&1)))
      )
      |> Enum.uniq()
      |> Enum.take(10)

    Enum.reduce_while(peers, {:error, :unavailable}, fn peer, _ ->
      result =
        with {:ok, response} <-
               request.(
                 :get,
                 peer,
                 "/_matrix/federation/v1/make_knock/" <>
                   escape(ref) <> "/" <> escape(user) <> "?ver=11&ver=12",
                 nil
               ),
             version when version in ["11", "12"] <- response["room_version"],
             template when is_map(template) <- response["event"],
             true <- is_map(template["content"]),
             true <-
               template["room_id"] == ref and template["sender"] == user and
                 template["state_key"] == user and template["type"] == "m.room.member" and
                 get_in(template, ["content", "membership"]) == "knock",
             {:ok, seed, key} <- Signing.config(),
             profile <-
               LakehouseMatrix.ClientProfiles.membership(
                 Repo.get!(LakehouseIam.Schema.Principal, principal)
               ),
             content <-
               Map.merge(profile, template["content"])
               |> Map.merge(Map.take(params, ["reason"]))
               |> Map.reject(fn {_, v} -> is_nil(v) end),
             event <-
               Event.sign(
                 template
                 |> Map.put("origin_server_ts", System.system_time(:millisecond))
                 |> Map.put("content", content),
                 version,
                 seed,
                 key,
                 Identity.homeserver_domain()
               ),
             :ok <- Event.validate(event, version),
             :ok <- LakehouseMatrix.AccountModeration.check(principal),
             id <- Event.id(event, version),
             {:ok, %{"knock_room_state" => stripped}} <-
               request.(
                 :put,
                 peer,
                 "/_matrix/federation/v1/send_knock/" <> escape(ref) <> "/" <> escape(id),
                 event
               ),
             true <- is_list(stripped) and length(stripped) <= 100 do
          Repo.transaction(fn ->
            ClientStore.lock!()
            LakehouseMatrix.AccountModeration.require!(principal)
            metadata = Invites.ensure_metadata!(ref, version, stripped)

            unless Memberships.membership(metadata.local_room_id, principal) not in ~w(join invite ban),
              do: Repo.rollback(:forbidden)

            Repo.insert_all(
              "matrix_pdus",
              [
                %{
                  event_id: id,
                  local_room_id: ClientStore.dump_id(metadata.local_room_id),
                  pdu: event,
                  outlier: true,
                  received_at: ClientStore.now()
                }
              ],
              on_conflict: :nothing
            )

            ctx = %Context{
              room_id: metadata.local_room_id,
              event_id: id,
              type: "m.room.member",
              state_key: user,
              sender: user,
              principal_id: principal,
              content: content,
              origin_server_ts: event["origin_server_ts"]
            }

            {:ok, _} = Events.persist(ctx, %{"content" => content})

            {:ok, _} =
              Memberships.upsert_membership(metadata.local_room_id, principal, "knock", ctx)

            Repo.insert_all("matrix_state_changes", [
              %{
                local_room_id: ClientStore.dump_id(metadata.local_room_id),
                type: "m.room.member",
                state_key: user,
                event_id: id
              }
            ])

            stripped =
              Enum.filter(
                stripped,
                &(is_map(&1) and is_binary(&1["type"]) and is_binary(&1["state_key"]) and
                    is_map(&1["content"]))
              )
              |> Enum.map(&Map.take(&1, ~w(type state_key sender content)))
              |> Enum.reject(&(&1["type"] == "m.room.member" and &1["state_key"] == user))

            state = %{
              "events" => stripped ++ [Map.take(event, ~w(type state_key sender content))]
            }

            Repo.insert_all(
              "matrix_pending_invites",
              [
                %{
                  local_room_id: ClientStore.dump_id(metadata.local_room_id),
                  user_id: user,
                  origin: peer,
                  event_id: id,
                  stripped_state: state
                }
              ],
              on_conflict: [set: [origin: peer, event_id: id, stripped_state: state]],
              conflict_target: [:local_room_id, :user_id]
            )

            %{"room_id" => ref}
          end)
        else
          {:error, _} = error -> error
          _ -> {:error, :invalid_param}
        end

      if match?({:ok, _}, result), do: {:halt, result}, else: {:cont, result}
    end)
  rescue
    _ -> {:error, :unavailable}
  end

  defp escape(value), do: URI.encode(value, &URI.char_unreserved?/1)
end
