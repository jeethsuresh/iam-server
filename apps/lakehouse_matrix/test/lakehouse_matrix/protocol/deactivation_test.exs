defmodule LakehouseMatrix.DeactivationTest do
  use LakehouseMatrix.DataCase, async: false
  alias LakehouseIam.{Accounts, Repo}
  alias LakehouseIam.Schema.Principal

  alias LakehouseMatrix.{
    ClientLogin,
    ClientRooms,
    ClientStore,
    Deactivation,
    DeactivationWorker,
    Fixtures,
    Identity,
    Matrix,
    Memberships
  }

  alias LakehouseMatrix.Protocol.Graph

  setup do
    keys = [:native_event_graph, :signing_key, :signing_key_id]
    old = Map.new(keys, &{&1, Application.get_env(:lakehouse_matrix, &1)})
    Application.put_env(:lakehouse_matrix, :native_event_graph, true)

    Application.put_env(
      :lakehouse_matrix,
      :signing_key,
      Base.encode64(<<0::256>>, padding: false)
    )

    Application.put_env(:lakehouse_matrix, :signing_key_id, "ed25519:test")

    on_exit(fn ->
      for {key, value} <- old do
        if is_nil(value),
          do: Application.delete_env(:lakehouse_matrix, key),
          else: Application.put_env(:lakehouse_matrix, key, value)
      end
    end)

    user = Fixtures.user_fixture("deactuser")
    other = Fixtures.user_fixture("deactother")
    {:ok, session} = ClientLogin.open(user, %{"device_id" => "D", "refresh_token" => true})
    {:ok, %{"room_id" => ref}} = ClientRooms.create(user.id, %{"preset" => "public_chat"})
    {:ok, _} = Matrix.join_room(other.id, ref)
    {:ok, local} = Identity.parse_room_id(ref)

    {:ok, event} =
      Graph.send(local, Identity.user_id(user.username), "m.room.message", %{
        "body" => "Preserved history"
      })

    %{user: user, other: other, session: session, ref: ref, local: local, event: event}
  end

  defp close(user, erase \\ false) do
    params = %{"erase" => erase}
    assert {:error, {:uia, challenge}} = Deactivation.deactivate(user.id, "D", params)

    auth = %{
      "type" => "m.login.password",
      "identifier" => %{"type" => "m.id.user", "user" => Identity.user_id(user.username)},
      "password" => "password123",
      "session" => challenge["session"]
    }

    Deactivation.deactivate(user.id, "D", Map.put(params, "auth", auth))
  end

  test "deactivation revokes all credentials without erasing room history by default and cannot be approved or bootstrapped again",
       c do
    {:ok, iam} = LakehouseIam.Auth.Sessions.issue(c.user.username, :browser)

    {:ok, grant} =
      LakehouseIam.Apps.Grants.upsert(
        c.user.id,
        "https://chat.gravitas.cool",
        ["chats.read"],
        :all,
        []
      )

    {:ok, app} = LakehouseIam.Apps.Tokens.issue(grant)

    ClientStore.put_data(c.user.id, "", "m.secret_storage.key.test", %{
      "secret" => "client ciphertext"
    })

    assert {:ok, %{"id_server_unbind_result" => "success"}} = close(c.user)
    account = Repo.get!(Principal, c.user.id)
    refute account.active
    assert account.matrix_deactivated
    assert ClientLogin.authenticate(c.session["access_token"]) == :error
    assert {:error, :unknown_token} = ClientLogin.refresh(c.session["refresh_token"])
    assert LakehouseIam.Auth.Token.verify(iam.token) == :error
    assert {:error, _} = LakehouseIam.Apps.Tokens.verify_access(app.access_token)
    refute Accounts.password_valid?(c.user.username, "password123")
    assert {:error, :deactivated} = Accounts.set_active(c.user.id, true)
    assert {:error, :deactivated} = Accounts.set_password(c.user.id, "another password")
    assert ClientStore.get_data(c.user.id, "", "m.secret_storage.key.test") == nil

    assert {:error, :user_deactivated} =
             ClientStore.put_data(c.user.id, "", "m.secret_storage.key.late", %{
               "secret" => "late ciphertext"
             })

    assert {:error, :user_deactivated} =
             LakehouseMatrix.ClientKeys.upload(c.user.id, "late-device", c.user.username, %{})

    assert {:error, :user_deactivated} =
             LakehouseMatrix.KeyBackups.create(c.user.id, %{
               "algorithm" => "m.megolm_backup.v1.curve25519-aes-sha2",
               "auth_data" => %{"public_key" => "key"}
             })

    assert {:error, :user_deactivated} =
             LakehouseMatrix.Ephemeral.set_presence(c.user.id, %{"presence" => "online"})

    assert {:error, :user_deactivated} = ClientStore.create_filter(c.user.id, %{})
    assert {:error, :user_deactivated} = LakehouseMatrix.CrossSigning.upload(c.user.id, %{})
    assert {:error, :user_deactivated} = LakehouseMatrix.CrossSigning.signatures(c.user.id, %{})
    assert {:error, :user_deactivated} = LakehouseMatrix.OpenId.issue(c.user.id)

    assert {:error, :user_deactivated} =
             ClientStore.send_to_device(
               c.user.id,
               "D",
               c.user.username,
               "m.test",
               "late-envelope",
               %{}
             )

    assert {:error, :user_deactivated} =
             LakehouseMatrix.Reports.submit(
               c.user.id,
               "user",
               Identity.user_id(c.other.username),
               %{"reason" => "Late report"}
             )

    assert {:error, :user_deactivated} =
             LakehouseMatrix.Ephemeral.typing(
               c.user.id,
               c.ref,
               Identity.user_id(c.user.username),
               %{"typing" => true}
             )

    assert {:error, :user_deactivated} =
             ClientRooms.receipt(c.user.id, c.ref, "m.read", c.event["event_id"], %{})

    assert Repo.one(
             from p in "matrix_user_presence",
               where: p.principal_id == type(^c.user.id, :binary_id),
               select: p.content
           )["presence"] == "offline"

    assert {:ok, event} = ClientRooms.event(c.other.id, c.ref, c.event["event_id"])
    assert event["content"]["body"] == "Preserved history"
    assert :worked = DeactivationWorker.deliver_once()
    assert Memberships.membership(c.local, c.user.id) == "leave"
    assert :idle = DeactivationWorker.deliver_once()

    assert {:error, :user_deactivated} =
             Graph.send(c.local, Identity.user_id(c.user.username), "m.room.message", %{
               "body" => "blocked"
             })

    old_admin = Application.get_env(:lakehouse_iam, :admin_username)
    old_password = Application.get_env(:lakehouse_iam, :admin_password)

    try do
      Application.put_env(:lakehouse_iam, :admin_username, c.user.username)
      Application.put_env(:lakehouse_iam, :admin_password, "bootstrap password")
      assert :ok = LakehouseIam.Bootstrap.run()
      refute Repo.get!(Principal, c.user.id).active
      refute Accounts.password_valid?(c.user.username, "bootstrap password")
    after
      Application.put_env(:lakehouse_iam, :admin_username, old_admin)
      Application.put_env(:lakehouse_iam, :admin_password, old_password)
    end
  end

  test "erase preserves copies for old members, prunes later members and preserves other accounts' secret storage",
       c do
    ClientStore.put_data(c.other.id, "", "m.secret_storage.key.other", %{
      "secret" => "other ciphertext"
    })

    assert {:ok, _} = close(c.user, true)
    assert :worked = DeactivationWorker.deliver_once()
    later = Fixtures.user_fixture("deactlater")
    {:ok, _} = Matrix.join_room(later.id, c.ref)
    assert {:ok, old} = ClientRooms.event(c.other.id, c.ref, c.event["event_id"])
    assert old["content"]["body"] == "Preserved history"
    assert {:ok, fresh} = ClientRooms.event(later.id, c.ref, c.event["event_id"])
    assert fresh["content"] == %{}

    assert ClientStore.get_data(c.other.id, "", "m.secret_storage.key.other") == %{
             "secret" => "other ciphertext"
           }

    assert Accounts.active?(Repo.get!(Principal, c.other.id))
  end

  test "UIA binds erasure choice, actor and device before any account is closed", c do
    assert {:error, :invalid_param} =
             Deactivation.deactivate(c.user.id, "D", %{"erase" => "true"})

    assert {:error, {:uia, challenge}} =
             Deactivation.deactivate(c.user.id, "D", %{"erase" => false})

    auth = %{
      "type" => "m.login.password",
      "user" => c.user.username,
      "password" => "password123",
      "session" => challenge["session"]
    }

    assert {:error, {:uia, _}} =
             Deactivation.deactivate(c.user.id, "D", %{"erase" => true, "auth" => auth})

    assert {:error, {:uia, _}} =
             Deactivation.deactivate(c.other.id, "D", %{"erase" => false, "auth" => auth})

    assert {:error, {:uia, _}} =
             Deactivation.deactivate(c.user.id, "other-device", %{
               "erase" => false,
               "auth" => auth
             })

    assert Accounts.active?(Repo.get!(Principal, c.user.id))
    assert Accounts.active?(Repo.get!(Principal, c.other.id))
  end

  test "a lost worker lease cannot delete or release a newer claim", c do
    assert {:ok, _} = close(c.user)
    replacement = Ecto.UUID.generate()

    assert :worked =
             DeactivationWorker.deliver_once(fn _, _ ->
               Repo.update_all(
                 from(j in "matrix_deactivation_jobs",
                   where: j.principal_id == type(^c.user.id, :binary_id)
                 ),
                 set: [lease_token: ClientStore.dump_id(replacement)]
               )

               {:error, :simulated_disconnect}
             end)

    assert Repo.exists?(
             from j in "matrix_deactivation_jobs",
               where:
                 j.principal_id == type(^c.user.id, :binary_id) and
                   j.lease_token == type(^replacement, :binary_id)
           )

    assert Memberships.membership(c.local, c.user.id) == "join"
  end

  test "failed rooms cannot starve later room departures", c do
    assert {:ok, _} = close(c.user)

    Repo.update_all(
      from(m in LakehouseMatrix.Schema.RoomMembership,
        where: m.room_id == ^c.local and m.principal_id == ^c.user.id
      ),
      set: [membership_state: %{"membership" => "leave"}]
    )

    now = ClientStore.now()

    ids =
      for i <- 1..25, do: "00000000-0000-4000-8000-" <> String.pad_leading(to_string(i), 12, "0")

    Repo.insert_all(
      "rooms",
      Enum.map(
        ids,
        &%{
          id: ClientStore.dump_id(&1),
          name: "Queued room",
          visibility: "private",
          inserted_at: now,
          updated_at: now
        }
      )
    )

    Repo.insert_all(
      "room_memberships",
      Enum.map(
        ids,
        &%{
          id: Ecto.UUID.bingenerate(),
          room_id: ClientStore.dump_id(&1),
          principal_id: ClientStore.dump_id(c.user.id),
          membership_state: %{"membership" => "join"},
          inserted_at: now,
          updated_at: now
        }
      )
    )

    owner = self()

    fail = fn _, room ->
      send(owner, {:attempted, room})
      {:error, :unavailable}
    end

    assert :worked = DeactivationWorker.deliver_once(fail)
    for id <- Enum.take(ids, 20), do: assert_receive({:attempted, ^id})

    Repo.update_all(
      from(j in "matrix_deactivation_jobs", where: j.principal_id == type(^c.user.id, :binary_id)),
      set: [available_at: now]
    )

    succeed = fn _, room ->
      send(owner, {:attempted, room})

      Repo.update_all(
        from(m in LakehouseMatrix.Schema.RoomMembership,
          where: m.room_id == ^room and m.principal_id == ^c.user.id
        ),
        set: [membership_state: %{"membership" => "leave"}]
      )

      {:ok, %{}}
    end

    assert :worked = DeactivationWorker.deliver_once(succeed)
    for id <- Enum.drop(ids, 20), do: assert_receive({:attempted, ^id})
    refute_receive {:attempted, _}
  end

  test "an invalid job cannot close rooms or remove grants for an active account", c do
    {:ok, grant} =
      LakehouseIam.Apps.Grants.upsert(
        c.user.id,
        "https://chat.gravitas.cool",
        ["chats.read"],
        :all,
        []
      )

    Repo.insert_all("matrix_deactivation_jobs", [
      %{
        principal_id: ClientStore.dump_id(c.user.id),
        available_at: ClientStore.now(),
        attempts: 0
      }
    ])

    assert :worked = DeactivationWorker.deliver_once()
    assert Repo.get(LakehouseIam.Schema.AppGrant, grant.id)
    assert Accounts.active?(Repo.get!(Principal, c.user.id))
    assert Memberships.membership(c.local, c.user.id) == "join"
  end
end
