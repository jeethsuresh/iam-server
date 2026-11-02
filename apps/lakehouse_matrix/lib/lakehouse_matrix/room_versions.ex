defmodule LakehouseMatrix.RoomVersions do
  @moduledoc "Confirmed peer capabilities and the highest mutually supported stable room version."
  import Ecto.Query
  alias LakehouseIam.Repo
  alias LakehouseMatrix.{ClientStore, Identity}
  alias LakehouseMatrix.Federation.Transport
  alias LakehouseMatrix.Protocol.Event

  @path "/_matrix/federation/unstable/cool.gravitas/room_versions"
  @ttl 3600
  @refresh 300

  defp refresh_interval,
    do: Application.get_env(:lakehouse_matrix, :room_version_refresh_seconds, @refresh)

  def enabled?, do: Application.get_env(:lakehouse_matrix, :automatic_room_versions, false)

  def available,
    do:
      Map.new(
        if(LakehouseMatrix.Protocol.Rooms.enabled?(), do: Event.versions(), else: ["11"]),
        &{&1, "stable"}
      )

  def advertised, do: %{"server_name" => Identity.homeserver_domain(), "available" => available()}

  def domains(users) when is_list(users) do
    for user <- users,
        {:ok, server} <- [Event.user_domain(user)],
        server != Identity.homeserver_domain(),
        uniq: true,
        do: server
  end

  def domains(_), do: []

  # Local preference order is explicit: arbitrary/experimental peer version names
  # are never sorted numerically or mistaken for implemented stable versions.
  def best(lists) do
    Enum.find(Enum.reverse(Event.versions()), fn version ->
      Map.has_key?(available(), version) and Enum.all?(lists, &(version in &1))
    end)
  end

  def preferred(invites) do
    if enabled?() do
      servers = domains(invites)
      Enum.each(servers, &refresh/1)

      case common(servers) do
        {:ok, version} -> version
        {:error, :waiting_for_capabilities} -> hd(Event.versions())
        {:error, :no_common_version} -> nil
      end
    else
      if domains(invites) == [], do: List.last(Event.versions()), else: hd(Event.versions())
    end
  end

  def common(servers) do
    now = ClientStore.now()
    snapshots = Enum.map(servers, &snapshot/1)

    cond do
      Enum.any?(snapshots, fn row ->
        is_nil(row) or is_nil(row.confirmed_at) or DateTime.diff(now, row.confirmed_at) >= @ttl
      end) ->
        {:error, :waiting_for_capabilities}

      version = best(Enum.map(snapshots, & &1.versions)) ->
        {:ok, version}

      true ->
        {:error, :no_common_version}
    end
  end

  def snapshot(server) do
    Repo.one(
      from r in "matrix_peer_room_versions",
        where: r.server_name == ^server,
        select: %{
          versions: r.versions,
          confirmed_at: type(r.confirmed_at, :utc_datetime_usec),
          retry_at: type(r.retry_at, :utc_datetime_usec),
          source: r.source
        }
    )
  end

  def refresh(server, force \\ false) do
    row = snapshot(server)

    if force or is_nil(row) or DateTime.compare(row.retry_at, ClientStore.now()) != :gt do
      result =
        case Application.get_env(:lakehouse_matrix, :room_version_fetcher) do
          fetcher when is_function(fetcher, 1) -> fetcher.(server)
          _ -> fetch(server)
        end

      case result do
        {:ok, versions} when is_list(versions) ->
          case record(server, versions, "capabilities") do
            :ok -> :ok
            _ -> failed(server)
          end

        _ ->
          failed(server)
      end
    else
      :ok
    end
  end

  # Only call with the origin already authenticated by federation middleware.
  def observe(server, versions) do
    row = snapshot(server)

    if row && row.source == "capabilities" && row.confirmed_at &&
         DateTime.diff(ClientStore.now(), row.confirmed_at) < @ttl do
      :ok
    else
      record(server, versions, "signed_make_join")
    end
  end

  defp record(server, versions, source) do
    with {:ok, _} <- Transport.server_name(server),
         true <-
           is_list(versions) and length(versions) <= 128 and
             Enum.all?(versions, &(is_binary(&1) and byte_size(&1) in 1..128)) do
      now = ClientStore.now()
      versions = Enum.uniq(versions)

      values = %{
        server_name: server,
        versions: versions,
        confirmed_at: now,
        retry_at: DateTime.add(now, refresh_interval(), :second),
        source: source
      }

      Repo.insert_all("matrix_peer_room_versions", [values],
        on_conflict: {:replace, [:versions, :confirmed_at, :retry_at, :source]},
        conflict_target: [:server_name]
      )

      :ok
    else
      _ -> {:error, :invalid_capabilities}
    end
  end

  defp failed(server) do
    values = %{
      server_name: server,
      versions: [],
      confirmed_at: nil,
      retry_at: DateTime.add(ClientStore.now(), refresh_interval(), :second),
      source: "unavailable"
    }

    # A timeout/401 never invents support, deletes a last good observation, or
    # turns an existing conversation into a downgrade candidate.
    Repo.insert_all("matrix_peer_room_versions", [values],
      on_conflict: {:replace, [:retry_at]},
      conflict_target: [:server_name]
    )

    {:error, :unavailable}
  end

  defp fetch(server) do
    case Map.get(Application.get_env(:lakehouse_matrix, :room_version_sources, %{}), server) do
      %{"base_url" => url, "access_token" => token} ->
        uri = URI.parse(url)
        endpoint = %{host: uri.host, tls_name: uri.host, port: uri.port, authority: uri.authority}

        with {:ok, body} <-
               Transport.fetch(endpoint, "/_matrix/client/v3/capabilities",
                 headers: [{"authorization", "Bearer " <> token}],
                 max_bytes: 65_536
               ),
             available when is_map(available) <-
               get_in(body, ["capabilities", "m.room_versions", "available"]) do
          {:ok, for({version, "stable"} <- available, do: version)}
        else
          _ -> {:error, :unavailable}
        end

      _ ->
        with {:ok, %{"server_name" => ^server, "available" => available}} when is_map(available) <-
               Transport.request(:get, server, @path),
             do: {:ok, for({version, "stable"} <- available, do: version)},
             else: (_ -> {:error, :unavailable})
    end
  end
end
