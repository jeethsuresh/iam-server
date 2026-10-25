defmodule LakehouseMatrix.ClientProfiles do
  @moduledoc "Account profiles, membership profile updates and a directory limited to shared-room users."
  import Ecto.Query
  alias LakehouseIam.{Accounts, Repo}
  alias LakehouseMatrix.{ClientRooms, ClientStore, ClientSync, Identity, Memberships}
  alias LakehouseMatrix.Protocol.{Event, Policy}
  alias LakehouseMatrix.Federation.Transport

  def local(principal) do
    saved = (principal.meta || %{})["matrix_profile"] || %{}
    saved = if is_map(saved), do: saved, else: %{}

    Map.merge(
      %{"displayname" => principal.username, "avatar_url" => nil},
      Map.take(saved, ~w(displayname avatar_url))
    )
  end

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
               is_map(response) and
                 Enum.all?(Map.take(response, ~w(displayname avatar_url)), fn {_, value} ->
                   is_nil(value) or (is_binary(value) and byte_size(value) <= 4096)
                 end) do
          {:ok, Map.take(response, ~w(displayname avatar_url))}
        else
          _ -> {:error, :not_found}
        end
    end
  end

  def put(principal, user, field, value) do
    with true <- field in ~w(displayname avatar_url),
         true <-
           is_nil(value) or
             (is_binary(value) and String.valid?(value) and byte_size(value) <= 4096),
         true <- field != "avatar_url" or valid_avatar?(value) do
      Policy.transaction(fn ->
        ClientStore.lock!()

        account =
          Repo.one!(
            from p in LakehouseIam.Schema.Principal, where: p.id == ^principal, lock: "FOR UPDATE"
          )

        unless user == Identity.user_id(account.username), do: Repo.rollback(:forbidden)
        profile = Map.put(local(account), field, value)
        meta = Map.put(account.meta || %{}, "matrix_profile", profile)
        account |> Ecto.Changeset.change(meta: meta) |> Repo.update!()

        content =
          Map.put(profile, "membership", "join") |> Map.reject(fn {_, value} -> is_nil(value) end)

        for room <- Memberships.joined_room_ids(principal) do
          case ClientRooms.persist(principal, room, "m.room.member", content, user) do
            {:ok, _} -> :ok
            {:error, reason} -> Repo.rollback(reason)
          end
        end

        LakehouseMatrix.Ephemeral.profile_changed!(principal)

        %{}
      end)
    else
      _ -> {:error, :invalid_param}
    end
  end

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
