defmodule LakehouseMatrix.AppstorePushTest do
  use LakehouseMatrix.DataCase, async: false
  alias LakehouseIam.{Protocols, Repo}
  alias LakehouseIam.Apps.Grants
  alias LakehouseIam.Protocols.{Delivery, Invocation}

  alias LakehouseMatrix.{
    AppstorePush,
    ClientRooms,
    ClientStore,
    Fixtures,
    Identity,
    Matrix,
    PushRules
  }

  @origin "https://chat.gravitas.cool"
  @store "https://apps.gravitas.cool"
  @specification Path.expand("../../../../protocols/appstore/1.0.0.json", __DIR__)
                 |> File.read!()
                 |> Jason.decode!()

  setup do
    for {app, values} <- [
          lakehouse_matrix: [
            native_event_graph: true,
            appstore_push_origin: @origin,
            signing_key: Base.encode64(<<0::256>>, padding: false),
            signing_key_id: "ed25519:test"
          ],
          lakehouse_iam: [
            public_url: "https://gravitas.cool",
            protocol_owners: %{"appstore" => @store},
            protocol_services: %{
              @store => %{"key" => String.duplicate("s", 48), "permissions" => []},
              @origin => %{
                "key" => String.duplicate("r", 48),
                "permissions" => ~w(protocols.read appstore.push appstore.push.broadcast)
              }
            }
          ]
        ] do
      for {key, value} <- values do
        previous = Application.get_env(app, key)
        Application.put_env(app, key, value)

        on_exit(fn ->
          if is_nil(previous),
            do: Application.delete_env(app, key),
            else: Application.put_env(app, key, previous)
        end)
      end
    end

    alice = Fixtures.user_fixture("pushalice")
    bob = Fixtures.user_fixture("pushbob")
    {:ok, river_grant} = Grants.upsert(bob.id, @origin, ["profile.name"], :all, [])
    {:ok, store_grant} = Grants.upsert(bob.id, @store, ["profile.name"], :all, [])

    {:ok, _} =
      Protocols.register(store_grant, %{"schema_version" => 1, "protocols" => [@specification]})

    {:ok, %{"room_id" => room}} = ClientRooms.create(alice.id, %{"preset" => "public_chat"})
    {:ok, _} = Matrix.join_room(bob.id, room)
    %{alice: alice, bob: bob, room: room, river_grant: river_grant, store_grant: store_grant}
  end

  defp message(
         ctx,
         txn,
         type \\ "m.room.message",
         content \\ %{"msgtype" => "m.text", "body" => "Private message"}
       ) do
    {:ok, %{"event_id" => event}} =
      ClientRooms.send(ctx.alice.id, "A", ctx.room, type, txn, content)

    event
  end

  defp queued, do: Repo.aggregate(from(o in "matrix_appstore_outbox"), :count)

  @tag skip: is_nil(System.get_env("MATRIX_PUSH_INTEROP_APPSTORE_BINARY"))
  test "real Matrix event and PCR delivery reach Private Store's stream and acknowledgement",
       ctx do
    event =
      message(ctx, "store-interop", "m.room.encrypted", %{
        "algorithm" => "m.megolm.v1.aes-sha2",
        "ciphertext" => "private-encrypted-message"
      })

    ready = Path.join(System.tmp_dir!(), "matrix-store-#{Ecto.UUID.generate()}.json")
    on_exit(fn -> File.rm(ready) end)
    binary = System.fetch_env!("MATRIX_PUSH_INTEROP_APPSTORE_BINARY")

    port =
      Port.open({:spawn_executable, binary}, [
        :binary,
        :exit_status,
        :stderr_to_stdout,
        args: ["-test.run=^TestRiverMatrixNotificationInterop$", "-test.v", "-test.timeout=50s"],
        env:
          Enum.map(
            %{
              "MATRIX_PUSH_INTEROP_READY" => ready,
              "NOTIFICATION_INTEROP_SUBJECT" => ctx.bob.id,
              "MATRIX_PUSH_INTEROP_ROOM" => ctx.room,
              "MATRIX_PUSH_INTEROP_EVENT" => event
            },
            fn {k, v} -> {String.to_charlist(k), String.to_charlist(v)} end
          )
      ])

    assert :worked = AppstorePush.deliver_once()

    request = fn _, {key, envelope} ->
      deadline = System.monotonic_time(:millisecond) + 10_000
      wait_store(ready, deadline)
      %{"url" => url} = ready |> File.read!() |> Jason.decode!()

      case Req.post(url <> "/api/protocols/invoke",
             json: envelope,
             headers: [{"authorization", "Bearer " <> key}],
             retry: false
           ) do
        {:ok, %{status: 204}} -> :ok
        result -> flunk("Store rejected the real Matrix envelope: #{inspect(result)}")
      end
    end

    assert :worked = Protocols.deliver_once(request)
    await_store(port, "")
    assert queued() == 0
    assert Repo.aggregate(Delivery, :count) == 0
  end

  defp wait_store(path, deadline) do
    unless File.exists?(path) do
      if System.monotonic_time(:millisecond) > deadline, do: flunk("Store fixture did not start")
      Process.sleep(20)
      wait_store(path, deadline)
    end
  end

  defp await_store(port, log) do
    receive do
      {^port, {:data, chunk}} -> await_store(port, log <> chunk)
      {^port, {:exit_status, 0}} -> :ok
      {^port, {:exit_status, status}} -> flunk("Store fixture failed #{status}: #{log}")
    after
      50_000 ->
        Port.close(port)
        flunk("Store stream timed out: #{log}")
    end
  end

  test "local and encrypted events become private durable broadcasts, once per recipient", ctx do
    event = message(ctx, "plaintext")
    assert queued() == 1
    assert :worked = AppstorePush.deliver_once()
    assert queued() == 0
    assert Repo.aggregate(Invocation, :count) == 1
    [delivery] = Repo.all(Delivery)
    envelope = delivery.envelope
    assert envelope["sender"] == @origin
    assert envelope["subject"] == ctx.bob.id
    assert envelope["capability"] == "push.broadcast"
    payload = envelope["input"]["payload"]
    assert envelope["input"]["app"] == "river"
    assert payload["issuer"] == "https://gravitas.cool"
    assert payload["subject"] == ctx.bob.id
    assert payload["event_id"] == event
    assert payload["room_id"] == ctx.room
    assert Enum.sort(Map.keys(payload)) == ~w(event_id issuer kind room_id sequence subject)
    refute Jason.encode!(envelope) =~ "Private message"
    assert :idle = AppstorePush.deliver_once()

    message(ctx, "encrypted", "m.room.encrypted", %{
      "algorithm" => "m.megolm.v1.aes-sha2",
      "ciphertext" => "secret-ciphertext"
    })

    assert :worked = AppstorePush.deliver_once()
    refute Enum.any?(Repo.all(Delivery), &(Jason.encode!(&1.envelope) =~ "secret-ciphertext"))
  end

  test "retry after acceptance is idempotent even when unread counts change", ctx do
    message(ctx, "first")

    assert :worked =
             AppstorePush.deliver_once(fn sender, subject, params ->
               assert {:ok, _} = Protocols.invoke(sender, subject, params)
               {:error, :lost_receipt}
             end)

    assert queued() == 1
    message(ctx, "second")
    Repo.update_all("matrix_appstore_outbox", set: [available_at: ClientStore.now()])
    assert :worked = AppstorePush.deliver_once()
    assert Repo.aggregate(Invocation, :count) == 1
    assert :worked = AppstorePush.deliver_once()
    assert Repo.aggregate(Invocation, :count) == 2
  end

  test "read receipts, ignoring, leaving and grant revocation suppress pending alerts", ctx do
    event = message(ctx, "read")
    assert {:ok, _} = ClientRooms.receipt(ctx.bob.id, ctx.room, "m.read.private", event, %{})
    assert :worked = AppstorePush.deliver_once(fn _, _, _ -> flunk("read event escaped") end)
    message(ctx, "ignored")

    {:ok, _} =
      ClientStore.put_data(ctx.bob.id, "", "m.ignored_user_list", %{
        "ignored_users" => %{Identity.user_id(ctx.alice.username) => %{}}
      })

    assert :worked = AppstorePush.deliver_once(fn _, _, _ -> flunk("ignored event escaped") end)

    {:ok, _} =
      ClientStore.put_data(ctx.bob.id, "", "m.ignored_user_list", %{"ignored_users" => %{}})

    message(ctx, "revoked")
    Repo.delete!(ctx.river_grant)
    assert :worked = AppstorePush.deliver_once(fn _, _, _ -> flunk("revoked grant escaped") end)
    message(ctx, "no-grant")
    assert queued() == 0
  end

  test "muted rooms, absent subscriptions, rollback and disabled configuration send nothing",
       ctx do
    {:ok, _} =
      PushRules.mutate(ctx.bob.id, "room", ctx.room, "PUT", %{"actions" => ["dont_notify"]})

    message(ctx, "muted")
    assert queued() == 0
    {:ok, _} = PushRules.mutate(ctx.bob.id, "room", ctx.room, "DELETE", %{})

    assert {:error, :rolled_back} =
             Repo.transaction(fn ->
               message(ctx, "rollback")
               Repo.rollback(:rolled_back)
             end)

    assert queued() == 0
    {:ok, _} = Protocols.register(ctx.store_grant, %{"schema_version" => 1, "protocols" => []})
    message(ctx, "no-provider")
    assert queued() == 0
    Application.delete_env(:lakehouse_matrix, :appstore_push_origin)
    assert :idle = AppstorePush.deliver_once()
  end

  test "leaving a conversation cancels a queued alert even when its history stays readable",
       ctx do
    message(ctx, "left")
    {:ok, _} = Matrix.leave_room(ctx.bob.id, ctx.room)

    assert :worked =
             AppstorePush.deliver_once(fn _, _, _ -> flunk("left conversation escaped") end)

    assert queued() == 0
  end

  test "Matrix deactivation cancels a queued alert independently of shared account state", ctx do
    message(ctx, "deactivated")
    Repo.update!(Ecto.Changeset.change(ctx.bob, matrix_deactivated: true))

    assert :worked =
             AppstorePush.deliver_once(fn _, _, _ -> flunk("deactivated account escaped") end)

    assert queued() == 0
  end

  test "expired work is discarded and leases prevent a competing delivery", ctx do
    message(ctx, "leased")

    assert :worked =
             AppstorePush.deliver_once(fn _, _, _ ->
               assert :idle = AppstorePush.deliver_once()
               {:error, :offline}
             end)

    assert queued() == 1

    Repo.update_all("matrix_notifications",
      set: [ts: System.system_time(:millisecond) - 8 * 24 * 60 * 60 * 1000]
    )

    assert :idle = AppstorePush.deliver_once()
    assert queued() == 0
  end
end
