defmodule LakehouseMatrix.ClientLogin do
  @moduledoc "Device sessions, reusable refresh credentials and single-use login credentials. Only digests are persisted."
  import Ecto.Query
  alias LakehouseIam.{Accounts, Repo}
  alias LakehouseMatrix.{ClientStore, Identity}
  @access_ms 3_600_000
  @legacy_ms 7_776_000_000

  def open(principal, params) do
    device = params["device_id"] || String.slice(ClientStore.random(), 0, 12)
    name = params["initial_device_display_name"]
    refresh? = params["refresh_token"] == true

    if is_binary(device) and byte_size(device) in 1..255 and
         (is_nil(name) or (is_binary(name) and byte_size(name) <= 1024)) and
         params["refresh_token"] in [nil, true, false] do
      Repo.transaction(fn ->
        ClientStore.lock!()

        LakehouseMatrix.AccountModeration.require!(principal.id, :read)

        unless Accounts.active?(Repo.get!(LakehouseIam.Schema.Principal, principal.id)),
          do: Repo.rollback(:invalid_credentials)

        if LakehouseMatrix.CrossSigning.reserved_device_id?(principal.id, device),
          do: Repo.rollback(:invalid_param)

        {created, _} =
          Repo.insert_all(
            "matrix_devices",
            [
              %{
                principal_id: ClientStore.dump_id(principal.id),
                device_id: device,
                display_name: name,
                keys: %{},
                inserted_at: ClientStore.now(),
                updated_at: ClientStore.now()
              }
            ],
            on_conflict: :nothing,
            conflict_target: [:principal_id, :device_id]
          )

        if created > 0, do: LakehouseMatrix.Federation.DeviceKeys.changed!(principal.id, device)

        access = "mtx_" <> ClientStore.random()
        refresh = if refresh?, do: "mrt_" <> ClientStore.random()
        lifetime = if refresh?, do: @access_ms, else: @legacy_ms

        # A fresh login for an existing device replaces its session authority,
        # while retaining the client's device keys and pending key messages.
        Repo.delete_all(
          from s in "matrix_sessions",
            where: s.principal_id == type(^principal.id, :binary_id) and s.device_id == ^device
        )

        Repo.insert_all("matrix_sessions", [
          %{
            principal_id: ClientStore.dump_id(principal.id),
            device_id: device,
            token_hash: ClientStore.hash(access),
            refresh_hash: if(refresh, do: ClientStore.hash(refresh)),
            expires_at: DateTime.add(ClientStore.now(), lifetime, :millisecond),
            inserted_at: ClientStore.now()
          }
        ])

        %{
          "user_id" => Identity.user_id(principal.username),
          "device_id" => device,
          "access_token" => access,
          "expires_in_ms" => lifetime,
          "home_server" => Identity.homeserver_domain(),
          "well_known" => %{
            "m.homeserver" => %{"base_url" => LakehouseIam.Discovery.public_url()}
          }
        }
        |> then(fn body ->
          if refresh, do: Map.put(body, "refresh_token", refresh), else: body
        end)
      end)
    else
      {:error, :invalid_param}
    end
  end

  def authenticate("mtx_" <> _ = token) do
    digest = ClientStore.hash(token)

    case Repo.one(
           from s in "matrix_sessions",
             join: p in LakehouseIam.Schema.Principal,
             on: s.principal_id == p.id,
             where: s.token_hash == ^digest and p.active == true,
             select: {p, s.device_id, s.id, type(s.expires_at, :utc_datetime_usec)}
         ) do
      {p, device, id, expires} ->
        if DateTime.compare(expires, ClientStore.now()) == :gt,
          do: {:ok, p, device, id},
          else: :expired

      _ ->
        :error
    end
  end

  def authenticate(_), do: :error

  # Matrix permits retaining the existing refresh token. Keeping it until device
  # revocation makes lost refresh responses retryable without persisting plaintext
  # bearer credentials or an ambiguous rotation grace period.
  def refresh("mrt_" <> _ = token) do
    Repo.transaction(fn ->
      ClientStore.lock!()
      digest = ClientStore.hash(token)

      session =
        Repo.one(
          from s in "matrix_sessions",
            join: p in LakehouseIam.Schema.Principal,
            on: s.principal_id == p.id,
            where: s.refresh_hash == ^digest and p.active == true,
            select: {s.id, p.id}
        )

      unless session, do: Repo.rollback(:unknown_token)
      {session, principal} = session
      LakehouseMatrix.AccountModeration.require!(principal, :read)
      access = "mtx_" <> ClientStore.random()

      Repo.update_all(from(s in "matrix_sessions", where: s.id == ^session),
        set: [
          token_hash: ClientStore.hash(access),
          expires_at: DateTime.add(ClientStore.now(), @access_ms, :millisecond)
        ]
      )

      %{"access_token" => access, "expires_in_ms" => @access_ms}
    end)
  end

  def refresh(_), do: {:error, :unknown_token}

  def generate(principal, limit? \\ true, device \\ nil) do
    Repo.transaction(fn ->
      ClientStore.lock!()
      LakehouseMatrix.AccountModeration.require!(principal, :read)
      recent = DateTime.add(ClientStore.now(), -60, :second)

      if limit? and
           Repo.exists?(
             from t in "matrix_login_tokens",
               where: t.principal_id == type(^principal, :binary_id) and t.inserted_at > ^recent
           ),
         do: Repo.rollback(:rate_limited)

      token = "mlt_" <> ClientStore.random()

      Repo.insert_all("matrix_login_tokens", [
        %{
          token_hash: ClientStore.hash(token),
          principal_id: ClientStore.dump_id(principal),
          source_device: device,
          expires_at: DateTime.add(ClientStore.now(), 120, :second),
          inserted_at: ClientStore.now()
        }
      ])

      %{"login_token" => token, "expires_in_ms" => 120_000}
    end)
  end

  def redeem("mlt_" <> _ = token, params) do
    Repo.transaction(fn ->
      ClientStore.lock!()
      digest = ClientStore.hash(token)

      principal =
        Repo.one(
          from t in "matrix_login_tokens",
            join: p in LakehouseIam.Schema.Principal,
            on: t.principal_id == p.id,
            where:
              t.token_hash == ^digest and is_nil(t.used_at) and t.expires_at > ^ClientStore.now() and
                p.active == true,
            select: p
        )

      unless principal, do: Repo.rollback(:invalid_credentials)

      Repo.update_all(from(t in "matrix_login_tokens", where: t.token_hash == ^digest),
        set: [used_at: ClientStore.now()]
      )

      case open(principal, params) do
        {:ok, body} -> body
        {:error, reason} -> Repo.rollback(reason)
      end
    end)
  end

  def redeem(_, _), do: {:error, :invalid_credentials}
end
