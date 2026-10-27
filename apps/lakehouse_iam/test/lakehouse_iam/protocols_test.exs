defmodule LakehouseIam.ProtocolsTest do
  use LakehouseIam.DataCase
  alias LakehouseIam.{Accounts, Protocols}
  alias LakehouseIam.Apps.{Grants, Tokens}
  alias LakehouseIam.Protocols.{Spec, Registration, Invocation, Delivery, JsonSchema}

  @store "https://apps.example"
  @other "https://another-store.example"
  @sender "https://calendar.example"
  @appstore Path.expand("../fixtures/appstore-1.0.0.json", __DIR__)
            |> File.read!()
            |> Jason.decode!()

  setup do
    services = %{
      @store => %{"key" => String.duplicate("s", 48), "permissions" => ["protocols.read"]},
      @other => %{"key" => String.duplicate("o", 48), "permissions" => []},
      @sender => %{
        "key" => String.duplicate("c", 48),
        "permissions" => ["protocols.read", "appstore.push"]
      }
    }

    for {key, value} <- [protocol_services: services, protocol_owners: %{"appstore" => @store}] do
      prior = Application.get_env(:lakehouse_iam, key)
      Application.put_env(:lakehouse_iam, key, value)

      on_exit(fn ->
        if prior,
          do: Application.put_env(:lakehouse_iam, key, prior),
          else: Application.delete_env(:lakehouse_iam, key)
      end)
    end

    {:ok, user} = Accounts.register_user("registryuser", "password123", approve: true)
    {:ok, grant} = Grants.upsert(user.id, @store, ["profile.name"], :all, [])
    sender = %{origin: @sender, permissions: services[@sender]["permissions"]}
    {:ok, user: user, grant: grant, sender: sender}
  end

  defp registry(spec \\ @appstore), do: %{"schema_version" => 1, "protocols" => [spec]}

  defp invocation(id \\ "notify-1"),
    do: %{
      "id" => id,
      "protocol" => "appstore",
      "version" => "1.0.0",
      "capability" => "push.send",
      "input" => %{
        "app" => "spacetime",
        "device" => String.duplicate("a", 64),
        "payload" => %{"title" => "Dinner"}
      }
    }

  test "registration is idempotent; discovery hides providers and filters permission layers", %{
    user: user,
    grant: grant,
    sender: sender
  } do
    assert {:ok, :ok} = Protocols.register(grant, registry())
    assert {:ok, :ok} = Protocols.register(grant, registry())
    assert Repo.aggregate(Registration, :count) == 1
    {:ok, second} = Grants.upsert(user.id, @other, ["profile.name"], :all, [])
    assert {:ok, :ok} = Protocols.register(second, registry())
    [spec] = Protocols.subscribed(user.id, sender)
    assert Enum.map(spec["capabilities"], & &1["id"]) == ["push.send"]
    encoded = Jason.encode!(spec)
    refute encoded =~ @store
    refute encoded =~ @other
    refute encoded =~ grant.id
    assert Protocols.subscribed(Ecto.UUID.generate(), sender) == []
    assert Protocols.subscribed(user.id, %{sender | permissions: []}) == []

    assert length(
             Protocols.specifications(%{
               sender
               | permissions: sender.permissions ++ ["appstore.push.broadcast"]
             })
             |> hd()
             |> Map.fetch!("capabilities")
           ) == 2
  end

  test "protocol definitions are semver and immutable, and only the namespace owner can introduce them",
       %{user: user, grant: grant} do
    {:ok, other} = Grants.upsert(user.id, @other, ["profile.name"], :all, [])
    assert {:error, :unknown_protocol} = Protocols.register(other, registry())
    assert {:ok, _} = Protocols.register(grant, registry())

    changed =
      put_in(
        @appstore,
        ["capabilities", Access.at(0), "input", "properties", "app", "maxLength"],
        63
      )

    assert {:error, :version_conflict} = Protocols.register(grant, registry(changed))

    for version <- ["1", "1.0", "01.0.0", "latest"] do
      refute Protocols.valid_spec?(Map.put(@appstore, "version", version))
    end

    assert Protocols.valid_spec?(Map.put(@appstore, "version", "1.1.0-rc.1+build.2"))
    assert Repo.aggregate(Spec, :count) == 1
  end

  test "multicast is private, idempotent and independent per provider; retries survive failures",
       %{user: user, grant: grant, sender: sender} do
    assert {:ok, _} = Protocols.register(grant, registry())
    {:ok, other} = Grants.upsert(user.id, @other, ["profile.name"], :all, [])
    assert {:ok, _} = Protocols.register(other, registry())

    assert {:ok, %{"id" => "notify-1", "status" => "accepted"} = receipt} =
             Protocols.invoke(sender, user.id, invocation())

    assert {:ok, ^receipt} = Protocols.invoke(sender, user.id, invocation())
    assert Repo.aggregate(Delivery, :count) == 2

    assert {:ok, %{"status" => "accepted"}} =
             Protocols.invoke(sender, Ecto.UUID.generate(), invocation("unknown-user"))

    assert Repo.aggregate(Delivery, :count) == 2

    assert {:error, :id_conflict} =
             Protocols.invoke(
               sender,
               user.id,
               put_in(invocation(), ["input", "payload", "title"], "Different")
             )

    assert :worked =
             Protocols.deliver_once(fn url, {key, envelope} ->
               assert url in [
                        @store <> "/api/protocols/invoke",
                        @other <> "/api/protocols/invoke"
                      ]

               assert key in [String.duplicate("s", 48), String.duplicate("o", 48)]
               assert envelope["sender"] == @sender
               assert envelope["subject"] == user.id
               :retry
             end)

    assert Repo.aggregate(Delivery, :count) == 2
    Repo.update_all(Delivery, set: [available_at: DateTime.add(DateTime.utc_now(), -1, :second)])
    assert :worked = Protocols.deliver_once(fn _, _ -> :ok end)
    assert :worked = Protocols.deliver_once(fn _, _ -> :ok end)
    assert Repo.aggregate(Delivery, :count) == 0
    assert Repo.aggregate(Invocation, :count) == 2
  end

  test "permissions, payload schemas and exact versions are enforced before enqueue", %{
    user: user,
    grant: grant,
    sender: sender
  } do
    assert {:ok, _} = Protocols.register(grant, registry())
    assert {:error, _} = Protocols.invoke(%{sender | permissions: []}, user.id, invocation())

    assert {:error, _} =
             Protocols.invoke(sender, user.id, Map.put(invocation(), "version", "2.0.0"))

    assert {:error, _} =
             Protocols.invoke(sender, user.id, put_in(invocation(), ["input", "device"], "*"))

    assert {:error, _} =
             Protocols.invoke(sender, user.id, put_in(invocation(), ["input", "payload"], nil))

    assert {:error, _} =
             Protocols.invoke(
               sender,
               user.id,
               Map.put(invocation(), "callback", "http://localhost")
             )

    assert {:error, _} =
             Protocols.invoke(
               sender,
               user.id,
               put_in(invocation(), ["input", "url"], "http://localhost")
             )

    broadcast =
      invocation()
      |> Map.put("capability", "push.broadcast")
      |> Map.update!("input", &Map.delete(&1, "device"))

    assert {:error, _} = Protocols.invoke(sender, user.id, broadcast)

    assert {:ok, _} =
             Protocols.invoke(
               %{sender | permissions: sender.permissions ++ ["appstore.push.broadcast"]},
               user.id,
               broadcast
             )

    assert Repo.aggregate(Delivery, :count) == 1
  end

  test "unsubscribe and grant revocation cancel pending deliveries", %{
    user: user,
    grant: grant,
    sender: sender
  } do
    assert {:ok, _} = Protocols.register(grant, registry())
    assert {:ok, _} = Protocols.invoke(sender, user.id, invocation())
    assert {:ok, _} = Protocols.register(grant, %{"schema_version" => 1, "protocols" => []})
    assert Repo.aggregate(Delivery, :count) == 0
    assert {:ok, _} = Protocols.register(grant, registry())
    assert {:ok, _} = Protocols.invoke(sender, user.id, invocation("next"))
    assert :ok = Tokens.revoke_app(user.id, @store)
    assert Repo.aggregate(Delivery, :count) == 0
    assert Protocols.subscribed(user.id, sender) == []
    assert {:error, :forbidden} = Protocols.register(grant, registry())
  end

  test "the registry transports a second, unrelated protocol without appstore logic", %{
    user: user,
    grant: grant
  } do
    Application.put_env(:lakehouse_iam, :protocol_owners, %{"calendar" => @store})

    schema = %{
      "type" => "object",
      "properties" => %{"message" => %{"type" => "string", "minLength" => 1}},
      "required" => ["message"],
      "additionalProperties" => false
    }

    spec = %{
      "protocol" => "calendar",
      "version" => "0.1.0",
      "capabilities" => [
        %{
          "id" => "event.create",
          "permissions" => ["calendar.write"],
          "input" => schema,
          "output" => %{"type" => "object"}
        }
      ]
    }

    assert {:ok, _} = Protocols.register(grant, registry(spec))
    sender = %{origin: @sender, permissions: ["calendar.write"]}

    assert {:ok, _} =
             Protocols.invoke(sender, user.id, %{
               "id" => "event",
               "protocol" => "calendar",
               "version" => "0.1.0",
               "capability" => "event.create",
               "input" => %{"message" => "Dinner"}
             })

    assert Repo.aggregate(Delivery, :count) == 1
  end

  test "default HTTP transport uses the provider credential, preserves the public Host and retries",
       %{user: user, grant: grant, sender: sender} do
    defaults = Req.default_options()
    gateway = Application.get_env(:lakehouse_iam, :protocol_gateway)

    on_exit(fn ->
      Req.default_options(defaults)

      if gateway,
        do: Application.put_env(:lakehouse_iam, :protocol_gateway, gateway),
        else: Application.delete_env(:lakehouse_iam, :protocol_gateway)
    end)

    Application.put_env(:lakehouse_iam, :protocol_gateway, "relay.internal:443")
    assert {:ok, _} = Protocols.register(grant, registry())
    assert {:ok, _} = Protocols.invoke(sender, user.id, invocation("transport"))

    plug = fn conn, status ->
      assert conn.host == "relay.internal"
      assert conn.request_path == "/api/protocols/invoke"
      assert Plug.Conn.get_req_header(conn, "host") == ["apps.example"]

      assert Plug.Conn.get_req_header(conn, "authorization") == [
               "Bearer " <> String.duplicate("s", 48)
             ]

      {:ok, raw, conn} = Plug.Conn.read_body(conn)
      body = Jason.decode!(raw)
      assert body["sender"] == @sender
      assert body["subject"] == user.id
      Plug.Conn.send_resp(conn, status, String.duplicate("x", 16384))
    end

    Req.default_options(Keyword.put(defaults, :plug, fn conn -> plug.(conn, 503) end))
    assert :worked = Protocols.deliver_once()
    assert Repo.aggregate(Delivery, :count) == 1
    Repo.update_all(Delivery, set: [available_at: DateTime.add(DateTime.utc_now(), -1, :second)])
    Req.default_options(Keyword.put(defaults, :plug, fn conn -> plug.(conn, 200) end))
    assert :worked = Protocols.deliver_once()
    assert Repo.aggregate(Delivery, :count) == 0
  end

  test "schema subset rejects unsupported keywords and validates nested objects" do
    assert JsonSchema.schema?(%{"type" => "object"})
    refute JsonSchema.schema?(%{"type" => "object", "$ref" => "https://example/schema"})
    refute JsonSchema.schema?(%{"type" => "string", "pattern" => "["})
    s = %{"type" => "array", "items" => %{"type" => "integer", "minimum" => 1}, "maxItems" => 2}
    assert JsonSchema.schema?(s)
    assert JsonSchema.valid?(s, [1, 2])
    refute JsonSchema.valid?(s, [0])
    refute JsonSchema.valid?(s, [1, 2, 3])
  end
end
