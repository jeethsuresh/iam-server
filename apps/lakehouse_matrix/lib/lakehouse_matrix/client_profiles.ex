defmodule LakehouseMatrix.ClientProfiles do
  @moduledoc "Account profiles, membership profile updates and a directory limited to shared-room users."
  import Ecto.Query
  alias LakehouseIam.{Accounts, Repo}
  alias LakehouseMatrix.{ClientRooms, ClientStore, ClientSync, Identity, Memberships}
  alias LakehouseMatrix.Protocol.{Event, Policy}
  alias LakehouseMatrix.Federation.Transport

  def local(principal) do
    case (principal.meta || %{})["matrix_profile"] do
      saved when is_map(saved) -> Map.filter(saved, fn {key, _} -> valid_key?(key) end)
      _ -> %{"displayname" => principal.username, "avatar_url" => nil}
    end
  end

  def membership(principal), do: local(principal) |> Map.take(~w(displayname avatar_url))

  def valid_key?(key),
    do:
      is_binary(key) and byte_size(key) in 1..255 and
        (key in ~w(displayname avatar_url) or
           Regex.match?(~r/\A[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+\z/, key))

  def get(user) do
    case Identity.parse_user_id(user) do
      {:ok, name} ->
        with {:ok, principal} <- Accounts.fetch_user(name),
             true <- principal.active,
             do: {:ok, local(principal)},
             else: (_ -> {:error, :not_found})

      _ ->
        with {:ok, server} <- Event.user_domain(user),
             {:ok, response} <-
               Transport.request(
                 :get,
                 server,
                 "/_matrix/federation/v1/query/profile?user_id=" <> URI.encode_www_form(user),
                 nil
               ),
             true <-
               is_map(response) and byte_size(Jason.encode!(response)) <= 65_536 and
                 Enum.all?(Map.take(response, ~w(displayname avatar_url m.tz)), fn {_, value} ->
                   is_nil(value) or (is_binary(value) and byte_size(value) <= 4096)
                 end) do
          {:ok, Map.filter(response, fn {key, _} -> valid_key?(key) end)}
        else
          _ -> {:error, :not_found}
        end
    end
  end

  def put(principal, user, field, value), do: change(principal, user, field, {:put, value})
  def delete(principal, user, field), do: change(principal, user, field, :delete)

  defp change(principal, user, field, operation) do
    cond do
      is_binary(field) and byte_size(field) > 255 ->
        {:error, :key_too_large}

      not valid_key?(field) ->
        {:error, :invalid_param}

      not valid_value?(field, operation) ->
        {:error, :invalid_param}

      true ->
        Policy.transaction(fn ->
          ClientStore.lock!()
          LakehouseMatrix.AccountModeration.require!(principal)

          account =
            Repo.one!(
              from p in LakehouseIam.Schema.Principal,
                where: p.id == ^principal,
                lock: "FOR UPDATE"
            )

          unless user == Identity.user_id(account.username), do: Repo.rollback(:forbidden)

          profile =
            case operation do
              :delete -> Map.delete(local(account), field)
              {:put, value} -> Map.put(local(account), field, value)
            end

          if byte_size(Jason.encode!(profile)) > 65_536, do: Repo.rollback(:profile_too_large)
          meta = Map.put(account.meta || %{}, "matrix_profile", profile)
          account |> Ecto.Changeset.change(meta: meta) |> Repo.update!()

          if field == "avatar_url" and match?({:put, _}, operation),
            do: LakehouseMatrix.MediaReferences.publish_profile!(principal, profile["avatar_url"])

          if field in ~w(displayname avatar_url) do
            content =
              Map.take(profile, ~w(displayname avatar_url))
              |> Map.put("membership", "join")
              |> Map.reject(fn {_, value} -> is_nil(value) end)

            for room <- Memberships.joined_room_ids(principal) do
              case ClientRooms.persist(principal, room, "m.room.member", content, user) do
                {:ok, _} -> :ok
                {:error, reason} -> Repo.rollback(reason)
              end
            end

            LakehouseMatrix.Ephemeral.profile_changed!(principal)
          end

          %{}
        end)
    end
  end

  defp valid_value?(_, :delete), do: true

  defp valid_value?(field, {:put, value}) when field in ~w(displayname avatar_url m.tz) do
    (is_nil(value) or (is_binary(value) and String.valid?(value) and byte_size(value) <= 4096)) and
      (field != "avatar_url" or valid_avatar?(value))
  end

  defp valid_value?(_, {:put, _}), do: true

  def search(principal, params) do
    term = params["search_term"]

    with true <- is_binary(term) and String.valid?(term) and byte_size(term) <= 255,
         {:ok, limit} <- ClientSync.integer(params["limit"], 10, 1, 100) do
      current = ClientStore.position()

      members =
        Memberships.joined_room_ids(principal) |> Enum.flat_map(&ClientSync.state_at(&1, current))

      users =
        for event <- members,
            event["type"] == "m.room.member" and event["content"]["membership"] == "join",
            do: %{
              "user_id" => event["state_key"],
              "display_name" => text(event["content"]["displayname"]),
              "avatar_url" => text(event["content"]["avatar_url"])
            }

      own = Repo.get!(LakehouseIam.Schema.Principal, principal)
      own_profile = local(own)

      users =
        [
          %{
            "user_id" => Identity.user_id(own.username),
            "display_name" => own_profile["displayname"],
            "avatar_url" => own_profile["avatar_url"]
          }
          | users
        ]
        |> Enum.uniq_by(& &1["user_id"])

      term = String.downcase(term)

      matches =
        users
        |> Enum.filter(
          &(String.contains?(String.downcase(&1["user_id"]), term) or
              String.contains?(String.downcase(&1["display_name"] || ""), term))
        )
        |> Enum.sort_by(& &1["user_id"])

      {:ok, %{"limited" => length(matches) > limit, "results" => Enum.take(matches, limit)}}
    else
      _ -> {:error, :invalid_param}
    end
  end

  defp text(value), do: if(is_binary(value), do: value)

  defp valid_avatar?(value) when value in [nil, ""], do: true

  defp valid_avatar?("mxc://" <> ref) do
    with [server, id] <- String.split(ref, "/"),
         {:ok, _} <- Transport.server_name(server),
         do: LakehouseMatrix.Federation.Media.valid_id?(id),
         else: (_ -> false)
  end

  defp valid_avatar?(_), do: false
end
