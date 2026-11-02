defmodule LakehouseMatrix.Protocol.UpgradesTest do
  use LakehouseMatrix.DataCase, async: false

  alias LakehouseMatrix.{
    ClientRooms,
    ClientStore,
    Directory,
    Fixtures,
    Identity,
    Matrix,
    Memberships,
    RoomUpgrades
  }

  alias LakehouseMatrix.Protocol.{Authorization, Graph}
  alias LakehouseMatrix.Federation.RoomAccess

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

    %{alice: Fixtures.user_fixture("alice"), bob: Fixtures.user_fixture("bob")}
  end

  defp state(ref), do: RoomAccess.state(Graph.room_by_id(ref))

  test "upgrading v11 to v12 transfers state and aliases, invites without impersonation and retains private settings",
       ctx do
    alice = Identity.user_id("alice")
    bob = Identity.user_id("bob")
    alias_name = Identity.room_alias("upgrade")
    second = Identity.room_alias("second-upgrade")

    {:ok, %{"room_id" => old}} =
      ClientRooms.create(ctx.alice.id, %{
        "room_version" => "11",
        "room_alias_name" => "upgrade",
        "name" => "Before",
        "topic" => "Topic",
        "visibility" => "public",
        "invite" => [bob],
        "initial_state" => [
          %{
            "type" => "m.room.encryption",
            "state_key" => "",
            "content" => %{"algorithm" => "m.megolm.v1.aes-sha2"}
          },
          %{
            "type" => "cool.example.sensitive",
            "state_key" => "",
            "content" => %{"value" => "do not copy"}
          }
        ]
      })

    {:ok, old_id} = Identity.parse_room_id(old)
    {:ok, _} = Matrix.join_room(ctx.bob.id, old)
    {:ok, _} = Directory.put(ctx.alice.id, second, old)

    {:ok, _} =
      ClientRooms.put_state(ctx.alice.id, old, "m.room.canonical_alias", "", %{
        "alias" => alias_name,
        "alt_aliases" => [second]
      })

    {:ok, _} =
      ClientStore.put_data(ctx.alice.id, old, "m.tag", %{"tags" => %{"m.favourite" => %{}}})

    {:ok, _} =
      ClientStore.put_data(ctx.bob.id, old, "m.tag", %{"tags" => %{"m.lowpriority" => %{}}})

    {:ok, _} = ClientStore.put_data(ctx.bob.id, "", "m.direct", %{alice => [old]})

    {:ok, _} =
      LakehouseMatrix.PushRules.mutate(ctx.bob.id, "room", old, "PUT", %{"actions" => []})

    grant =
      Repo.insert!(
        LakehouseIam.Schema.AppGrant.changeset(%LakehouseIam.Schema.AppGrant{}, %{
          principal_id: ctx.bob.id,
          app_origin: "https://scoped.example",
          scopes: ["chats.read"],
          room_mode: :selected,
          room_ids: [old_id]
        })
      )

    before_count = Repo.aggregate(LakehouseMatrix.Schema.Room, :count)

    assert {:ok, %{"replacement_room" => replacement} = result} =
             RoomUpgrades.upgrade(ctx.alice.id, old, %{
               "new_version" => "12",
               "additional_creators" => [bob]
             })

    replacement_state = state(replacement)
    create = replacement_state[{"m.room.create", ""}]["content"]
    assert create["predecessor"] == %{"room_id" => old}
    assert create["additional_creators"] == [bob]

    assert replacement_state[{"m.room.encryption", ""}]["content"]["algorithm"] ==
             "m.megolm.v1.aes-sha2"

    assert replacement_state[{"m.room.name", ""}]["content"]["name"] == "Before"
    assert replacement_state[{"m.room.topic", ""}]["content"]["topic"] == "Topic"
    refute replacement_state[{"cool.example.sensitive", ""}]
    assert state(old)[{"m.room.tombstone", ""}]["content"]["replacement_room"] == replacement

    for ref <- [alias_name, second],
        do: assert({:ok, %{"room_id" => ^replacement}} = Directory.resolve(ref))

    assert replacement_state[{"m.room.canonical_alias", ""}]["content"]["alias"] == alias_name
    assert state(old)[{"m.room.canonical_alias", ""}]["content"] == %{}
    {:ok, new_id} = Identity.parse_room_id(replacement)
    assert Memberships.invited?(new_id, ctx.bob.id)
    refute Memberships.joined?(new_id, ctx.bob.id)

    assert ClientStore.get_data(ctx.alice.id, replacement, "m.tag") == %{
             "tags" => %{"m.favourite" => %{}}
           }

    assert is_nil(ClientStore.get_data(ctx.bob.id, replacement, "m.tag"))
    {:ok, _} = Matrix.join_room(ctx.bob.id, replacement)

    assert {:ok, %{"chunk" => members}} =
             LakehouseMatrix.ClientContext.members(ctx.bob.id, "device", replacement, %{})

    assert Enum.sort(Enum.map(members, & &1["state_key"])) == Enum.sort([alice, bob])
    assert Enum.all?(members, &(&1["room_id"] == replacement))

    assert {:ok, %{"actions" => []}} =
             LakehouseMatrix.PushRules.fetch(ctx.bob.id, "room", replacement, "actions")

    assert ClientStore.get_data(ctx.bob.id, replacement, "m.tag") == %{
             "tags" => %{"m.lowpriority" => %{}}
           }

    assert replacement in ClientStore.get_data(ctx.bob.id, "", "m.direct")[alice]
    assert Repo.get!(LakehouseIam.Schema.AppGrant, grant.id).room_ids == [old_id]
    assert Authorization.power(state(replacement), bob, "12") == :infinity
    refute Map.has_key?(state(replacement)[{"m.room.power_levels", ""}]["content"]["users"], bob)

    assert {:error, _} =
             ClientRooms.send(ctx.bob.id, "B", old, "m.room.message", "frozen", %{
               "body" => "old room"
             })

    assert {:ok, ^result} = RoomUpgrades.upgrade(ctx.alice.id, old, %{"new_version" => "12"})
    assert Repo.aggregate(LakehouseMatrix.Schema.Room, :count) == before_count + 1

    assert {:error, :already_upgraded} =
             RoomUpgrades.upgrade(ctx.alice.id, old, %{"new_version" => "11"})
  end

  for version <- ["9", "11"] do
    test "#{version}: a replacement includes the signed tombstone predecessor and preserves space and federation policy",
         ctx do
      version = unquote(version)
      bob = Identity.user_id("bob")

      {:ok, %{"room_id" => old}} =
        ClientRooms.create(ctx.alice.id, %{
          "creation_content" => %{
            "type" => "m.space",
            "m.federate" => false,
            "additional_creators" => [bob]
          },
          "preset" => "public_chat"
        })

      assert {:ok, %{"replacement_room" => replacement}} =
               RoomUpgrades.upgrade(ctx.alice.id, old, %{
                 "new_version" => version,
                 "additional_creators" => "ignored in v11"
               })

      metadata = Graph.room_by_id(replacement)
      assert metadata.version == version
      tombstone = state(old)[{"m.room.tombstone", ""}]
      create = state(replacement)[{"m.room.create", ""}]["content"]
      assert create["predecessor"] == %{"room_id" => old, "event_id" => tombstone["event_id"]}
      assert create["type"] == "m.space" and create["m.federate"] == false
      refute Map.has_key?(create, "additional_creators")
      assert Authorization.power(state(replacement), bob, version) == 100
      refute RoomAccess.allowed?(metadata, "outside.example")
    end
  end

  test "repairing an unjoined remote direct preserves encrypted history and moves only its owner's mapping",
       ctx do
    peer = "@legacy:remote.example"

    {:ok, %{"room_id" => old}} =
      ClientRooms.create(ctx.alice.id, %{"room_version" => "12", "invite" => [peer]})

    {:ok, old_id} = Identity.parse_room_id(old)

    {:ok, history} =
      Graph.send(old_id, Identity.user_id("alice"), "m.room.encrypted", %{
        "algorithm" => "m.megolm.v1.aes-sha2",
        "ciphertext" => "preserved ciphertext"
      })

    {:ok, _} =
      ClientRooms.put_state(ctx.alice.id, old, "m.room.encryption", "", %{
        "algorithm" => "m.megolm.v1.aes-sha2"
      })

    {:ok, _} =
      ClientStore.put_data(ctx.alice.id, "", "m.direct", %{
        peer => [old],
        "@other:remote.example" => ["!unchanged:remote.example"]
      })

    assert {:error, :invalid_param} = RoomUpgrades.repair_unjoined_direct(ctx.bob.id, old, peer)

    assert {:error, :invalid_param} =
             RoomUpgrades.repair_unjoined_direct(ctx.alice.id, old, "@wrong:remote.example")

    assert {:ok, %{"replacement_room" => replacement} = result} =
             RoomUpgrades.repair_unjoined_direct(ctx.alice.id, old, peer)

    assert Graph.room_by_id(replacement).version == "9"

    assert state(replacement)[{"m.room.encryption", ""}]["content"]["algorithm"] ==
             "m.megolm.v1.aes-sha2"

    assert state(replacement)[{"m.room.create", ""}]["content"]["predecessor"]["room_id"] == old
    assert Graph.event(history["event_id"]).pdu["content"]["ciphertext"] == "preserved ciphertext"
    assert state(replacement)[{"m.room.member", peer}]["content"]["membership"] == "invite"

    assert ClientStore.get_data(ctx.alice.id, "", "m.direct") == %{
             peer => [replacement],
             "@other:remote.example" => ["!unchanged:remote.example"]
           }

    assert {:ok, ^result} = RoomUpgrades.repair_unjoined_direct(ctx.alice.id, old, peer)
  end

  test "direct repair refuses rooms where another participant has joined", ctx do
    peer = "@legacy:remote.example"

    {:ok, %{"room_id" => old}} =
      ClientRooms.create(ctx.alice.id, %{
        "room_version" => "12",
        "invite" => [peer, Identity.user_id("bob")]
      })

    {:ok, _} = Matrix.join_room(ctx.bob.id, old)
    {:ok, _} = ClientStore.put_data(ctx.alice.id, "", "m.direct", %{peer => [old]})
    assert {:error, :invalid_param} = RoomUpgrades.repair_unjoined_direct(ctx.alice.id, old, peer)
    refute state(old)[{"m.room.tombstone", ""}]
  end

  test "only authorized members upgrade, and additional creators are not copied implicitly",
       ctx do
    bob = Identity.user_id("bob")
    {:ok, %{"room_id" => old}} = ClientRooms.create(ctx.alice.id, %{"preset" => "public_chat"})
    {:ok, _} = Matrix.join_room(ctx.bob.id, old)
    count = Repo.aggregate(LakehouseMatrix.Schema.Room, :count)
    assert {:error, _} = RoomUpgrades.upgrade(ctx.bob.id, old, %{"new_version" => "12"})

    assert {:error, :unsupported_room_version} =
             RoomUpgrades.upgrade(ctx.alice.id, old, %{"new_version" => "unknown"})

    assert {:error, :invalid_param} =
             RoomUpgrades.upgrade(ctx.alice.id, old, %{
               "new_version" => "12",
               "additional_creators" => ["invalid"]
             })

    assert Repo.aggregate(LakehouseMatrix.Schema.Room, :count) == count

    {:ok, %{"room_id" => trusted}} =
      ClientRooms.create(ctx.alice.id, %{"creation_content" => %{"additional_creators" => [bob]}})

    assert {:ok, %{"replacement_room" => replacement}} =
             RoomUpgrades.upgrade(ctx.alice.id, trusted, %{"new_version" => "12"})

    refute bob in Authorization.creators(state(replacement))
  end
end
