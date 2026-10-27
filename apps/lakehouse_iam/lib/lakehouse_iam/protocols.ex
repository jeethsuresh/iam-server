defmodule LakehouseIam.Protocols do
  @moduledoc "Private per-user providers, immutable semver contracts and durable multicast."
  import Ecto.Query
  alias LakehouseIam.{Repo, Apps.Scopes}
  alias LakehouseIam.Schema.{AppGrant, Principal}
  alias LakehouseIam.Protocols.{Spec, Registration, Invocation, Delivery, JsonSchema}

  def services, do: Application.get_env(:lakehouse_iam, :protocol_services, %{})
  def owners, do: Application.get_env(:lakehouse_iam, :protocol_owners, %{})

  def authenticate(raw) when is_binary(raw) and byte_size(raw) >= 32 do
    Enum.find_value(services(), fn {origin, service} ->
      if secure_equal(raw, service["key"]),
        do: %{origin: origin, permissions: service["permissions"] || []}
    end)
  end

  def authenticate(_), do: nil

  defp secure_equal(a, b) when is_binary(b) and byte_size(a) == byte_size(b),
    do: :crypto.hash_equals(a, b)

  defp secure_equal(_, _), do: false

  # Serializes modifications/idempotency decisions without holding a database
  # connection during delivery. Future protocols use exactly this same path.
  defp lock!, do: Ecto.Adapters.SQL.query!(Repo, "SELECT pg_advisory_xact_lock(731491, 1)", [])

  def register(grant, %{"schema_version" => 1, "protocols" => specs} = body)
      when is_list(specs) and length(specs) <= 32 do
    if Map.keys(body) |> Enum.sort() != ~w(protocols schema_version) do
      {:error, :invalid_registry}
    else
      Repo.transaction(fn ->
        lock!()
        # Recheck after acquiring the lock: revoking a grant must not resurrect it.
        current = Repo.get(AppGrant, grant.id) || Repo.rollback(:forbidden)

        unless current.principal_id == grant.principal_id and
                 current.app_origin == grant.app_origin,
               do: Repo.rollback(:forbidden)

        ids = Enum.map(specs, &register_spec!(current, &1))

        from(r in Registration, where: r.grant_id == ^current.id and r.spec_id not in ^ids)
        |> Repo.delete_all()

        :ok
      end)
    end
  end

  def register(_, _), do: {:error, :invalid_registry}

  defp register_spec!(grant, spec) do
    unless valid_spec?(spec), do: Repo.rollback(:invalid_specification)
    protocol = spec["protocol"]
    version = spec["version"]
    # A provider must be an operator-trusted backend. User JSON never supplies
    # destinations, delivery credentials, app names or provider identifiers.
    unless Map.has_key?(services(), grant.app_origin), do: Repo.rollback(:forbidden)
    existing = Repo.get_by(Spec, protocol: protocol, version: version)

    record =
      case existing do
        nil ->
          unless owners()[protocol] == grant.app_origin, do: Repo.rollback(:unknown_protocol)

          Repo.insert!(%Spec{
            protocol: protocol,
            version: version,
            owner: grant.app_origin,
            specification: spec
          })

        record ->
          unless record.specification == spec, do: Repo.rollback(:version_conflict)
          record
      end

    unless Repo.get_by(Registration, grant_id: grant.id, spec_id: record.id),
      do: Repo.insert!(%Registration{grant_id: grant.id, spec_id: record.id})

    record.id
  end

  def valid_spec?(%{"protocol" => name, "version" => version, "capabilities" => caps} = spec) do
    is_binary(name) and Regex.match?(~r/\A[a-z][a-z0-9.-]{0,63}\z/, name) and
      is_binary(version) and match?({:ok, _}, Version.parse(version)) and
      Enum.sort(Map.keys(spec)) == ~w(capabilities protocol version) and
      is_list(caps) and length(caps) in 1..32 and
      Enum.all?(caps, &valid_capability?/1) and
      length(Enum.uniq_by(caps, & &1["id"])) == length(caps) and
      byte_size(Jason.encode!(spec)) <= 32768
  end

  def valid_spec?(_), do: false

  defp valid_capability?(
         %{"id" => id, "permissions" => perms, "input" => input, "output" => output} = c
       ) do
    is_binary(id) and Regex.match?(~r/\A[a-z][a-z0-9.-]{0,63}\z/, id) and
      Enum.sort(Map.keys(c)) == ~w(id input output permissions) and
      is_list(perms) and length(perms) in 1..32 and
      Enum.all?(perms, &(is_binary(&1) and Regex.match?(~r/\A[a-z][a-z0-9.-]{0,127}\z/, &1))) and
      JsonSchema.schema?(input) and input["type"] == "object" and
      JsonSchema.schema?(output) and output["type"] == "object"
  end

  defp valid_capability?(_), do: false

  def specifications(sender) do
    Repo.all(from s in Spec, order_by: [s.protocol, s.version])
    |> Enum.map(&public_spec(&1.specification, sender))
    |> Enum.reject(&(&1["capabilities"] == []))
    |> sort_versions()
  end

  def subscribed(subject, sender) do
    if uuid?(subject) do
      registrations(subject)
      |> Repo.all()
      |> Enum.filter(fn {_, g, _} -> Map.has_key?(services(), g.app_origin) end)
      |> Enum.map(fn {_, _, s} -> public_spec(s.specification, sender) end)
      |> Enum.reject(&(&1["capabilities"] == []))
      |> Enum.uniq()
      |> sort_versions()
    else
      []
    end
  end

  defp sort_versions(specs) do
    Enum.sort(specs, fn a, b ->
      if a["protocol"] == b["protocol"],
        do: Version.compare(a["version"], b["version"]) != :lt,
        else: a["protocol"] < b["protocol"]
    end)
  end

  defp public_spec(spec, sender),
    do:
      Map.update!(
        spec,
        "capabilities",
        &Enum.filter(&1, fn c -> Scopes.covers?(sender.permissions, c["permissions"]) end)
      )

  defp registrations(subject) do
    from r in Registration,
      join: g in AppGrant,
      on: g.id == r.grant_id,
      join: p in Principal,
      on: p.id == g.principal_id and p.active == true,
      join: s in Spec,
      on: s.id == r.spec_id,
      where: g.principal_id == ^subject,
      select: {r, g, s}
  end

  def invoke(sender, subject, params) do
    with true <- uuid?(subject),
         %{
           "id" => id,
           "protocol" => protocol,
           "version" => version,
           "capability" => capability,
           "input" => input
         } <- params,
         true <- Enum.sort(Map.keys(params)) == ~w(capability id input protocol version),
         true <- is_binary(id) and byte_size(id) in 1..128,
         true <- is_binary(protocol) and is_binary(version) and is_binary(capability),
         true <- byte_size(Jason.encode!(input)) <= 8192,
         %Spec{} = spec <- Repo.get_by(Spec, protocol: protocol, version: version),
         cap when not is_nil(cap) <-
           Enum.find(spec.specification["capabilities"], &(&1["id"] == capability)),
         true <- Scopes.covers?(sender.permissions, cap["permissions"]),
         true <- JsonSchema.valid?(cap["input"], input) do
      enqueue(sender, subject, params, spec)
    else
      false -> {:error, :invalid_or_forbidden}
      _ -> {:error, :invalid_or_forbidden}
    end
  end

  defp enqueue(sender, subject, params, spec) do
    # Structural equality with a canonical key ordering makes retries independent
    # of JSON whitespace/object order. Receipts never contain provider results.
    digest = :crypto.hash(:sha256, :erlang.term_to_binary({subject, params})) |> Base.encode16()

    Repo.transaction(fn ->
      lock!()
      prior = Repo.get_by(Invocation, sender: sender.origin, request_id: params["id"])

      if prior do
        unless prior.digest == digest, do: Repo.rollback(:id_conflict)
      else
        now = DateTime.utc_now()

        count =
          Repo.aggregate(
            from(i in Invocation,
              where:
                i.sender == ^sender.origin and i.created_at > ^DateTime.add(now, -60, :second)
            ),
            :count
          )

        if count >= 1000, do: Repo.rollback(:rate_limited)

        invocation =
          Repo.insert!(%Invocation{
            sender: sender.origin,
            request_id: params["id"],
            digest: digest,
            created_at: now
          })

        registrations(subject)
        |> Repo.all()
        |> Enum.filter(fn {_, g, s} ->
          s.id == spec.id and Map.has_key?(services(), g.app_origin)
        end)
        |> Enum.each(fn {registration, _, _} ->
          envelope =
            Map.merge(params, %{
              "sender" => sender.origin,
              "subject" => subject,
              "issuer" => LakehouseIam.Discovery.public_url()
            })

          Repo.insert!(%Delivery{
            invocation_id: invocation.id,
            registration_id: registration.id,
            envelope: envelope,
            available_at: now
          })
        end)
      end

      %{"id" => params["id"], "status" => "accepted"}
    end)
  end

  def deliver_once(request \\ &request/2) do
    claimed =
      Repo.transaction(fn ->
        now = DateTime.utc_now()

        Repo.delete_all(
          from i in Invocation, where: i.created_at < ^DateTime.add(now, -7 * 86400, :second)
        )

        case Repo.one(
               from d in Delivery,
                 where: d.available_at <= ^now,
                 order_by: d.available_at,
                 limit: 1,
                 lock: "FOR UPDATE SKIP LOCKED"
             ) do
          nil ->
            nil

          item ->
            Repo.update!(
              Ecto.Changeset.change(item,
                lease: Ecto.UUID.generate(),
                available_at: DateTime.add(now, 60, :second)
              )
            )
        end
      end)

    case claimed do
      {:ok, nil} -> :idle
      {:ok, item} -> deliver(item, request)
      _ -> :idle
    end
  end

  defp deliver(item, request) do
    provider =
      Repo.one(
        from r in Registration,
          join: g in AppGrant,
          on: g.id == r.grant_id,
          join: p in Principal,
          on: p.id == g.principal_id and p.active == true,
          where: r.id == ^item.registration_id,
          select: g.app_origin
      )

    service = services()[provider]

    result =
      if service,
        do: request.(provider <> "/api/protocols/invoke", {service["key"], item.envelope}),
        else: :gone

    # Lease comparison prevents a slow former worker from deleting a new claim.
    query = from d in Delivery, where: d.id == ^item.id and d.lease == ^item.lease

    if result in [:ok, :gone] do
      Repo.delete_all(query)
    else
      delay = min(1800, 5 * Integer.pow(2, min(item.attempts, 9)))

      Repo.update_all(query,
        set: [
          attempts: item.attempts + 1,
          available_at: DateTime.add(DateTime.utc_now(), delay, :second),
          lease: nil
        ]
      )
    end

    :worked
  end

  defp request(url, {key, envelope}) do
    uri = URI.parse(url)
    gateway = Application.get_env(:lakehouse_iam, :protocol_gateway)
    destination = if gateway, do: "https://" <> gateway <> uri.path, else: url

    case Req.post(destination,
           json: envelope,
           headers: [{"authorization", "Bearer " <> key}, {"host", uri.host}],
           redirect: false,
           retry: false,
           receive_timeout: 10_000,
           connect_options: [timeout: 5_000, hostname: uri.host],
           into: fn _, pair -> {:halt, pair} end
         ) do
      {:ok, %{status: status}} when status in [200, 202, 204] -> :ok
      {:ok, %{status: 410}} -> :gone
      _ -> :retry
    end
  end

  defp uuid?(value), do: match?({:ok, _}, Ecto.UUID.cast(value))
end
