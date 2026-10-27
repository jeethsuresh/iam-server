defmodule LakehouseWeb.ParticipantSubgroupsTest do
  use LakehouseWeb.ConnCase
  alias LakehouseIam.{Contacts, ParticipantSets, Repo, Apps.Grants, Apps.Tokens}
  alias LakehouseMatrix.{DelegatedGroups, Identity, Memberships, RiverWorkspace, State}
  alias LakehouseWeb.MatrixFixtures

  setup tags do
    keys = [:native_event_graph, :signing_key, :signing_key_id]
    previous = Map.new(keys, &{&1, Application.get_env(:lakehouse_matrix, &1)})
    Application.put_env(:lakehouse_matrix, :native_event_graph, tags[:native_graph] || false)

    Application.put_env(
      :lakehouse_matrix,
      :signing_key,
      Base.encode64(:binary.copy(<<7>>, 32), padding: false)
    )

    Application.put_env(:lakehouse_matrix, :signing_key_id, "ed25519:test")

    on_exit(fn ->
      for {key, value} <- previous do
        if is_nil(value),
          do: Application.delete_env(:lakehouse_matrix, key),
          else: Application.put_env(:lakehouse_matrix, key, value)
      end
    end)

    people = for name <- ~w(setalice setbob setcara setdev), do: MatrixFixtures.user_fixture(name)

    grants =
      for p <- people do
        {:ok, grant} =
          Grants.upsert(
            p.id,
            "https://chat.gravitas.cool",
            ~w(chats.list chats.read chats.write groups.create groups.manage groups.join spaces.channels),
            :all,
            []
          )

        grant
      end

    %{people: people, grants: grants}
  end

  defp create(g, txn, kind \\ "group") do
    {:ok, room} = DelegatedGroups.create(g, %{"name" => txn, "kind" => kind, "txn_id" => txn})
    room
  end

  defp add(owner, member, person, room) do
    assert {:ok, _} =
             DelegatedGroups.membership(owner, room.id, %{
               "action" => "invite",
               "user_id" => Identity.user_id(person.username)
             })

    assert {:ok, _} = DelegatedGroups.membership(member, room.id, %{"action" => "accept"})
  end

  for native <- [false, true] do
    @tag native_graph: native
    test "membership moves subgroup without moving metadata or granting visibility (native #{native})",
         %{people: [a, b, c, _], grants: [ga, gb, gc, gd]} do
      space = create(ga, "space", "space")
      add(ga, gb, b, space)
      add(ga, gc, c, space)

      params = %{
        "name" => "Subset",
        "member_ids" => [Identity.user_id(b.username)],
        "context_id" => space.id,
        "txn_id" => "subset"
      }

      assert {:ok, conversation} = RiverWorkspace.conversation(ga, params)
      assert conversation.kind == "group"
      assert conversation.context_id == space.id
      singleton = ParticipantSets.current(conversation.id)
      assert singleton.subgroup_id == ParticipantSets.register!([ParticipantSets.principal(a.id)])
      assert Memberships.membership(conversation.id, b.id) == "invite"
      assert {:ok, _} = DelegatedGroups.membership(gb, conversation.id, %{"action" => "accept"})
      pair = ParticipantSets.current(conversation.id)
      refute pair.subgroup_id == singleton.subgroup_id
      assert {:ok, hierarchy} = DelegatedGroups.subgroups(ga, conversation.id)
      assert Enum.any?(hierarchy.containing_groups, &(&1.id == space.id))
      assert {:error, :forbidden} = DelegatedGroups.subgroups(gc, conversation.id)
      assert {:error, :forbidden} = DelegatedGroups.subgroups(gd, conversation.id)
      metadata = State.get(conversation.id, "cool.gravitas.river.context.v1")["content"]
      add(ga, gc, c, conversation)

      assert ParticipantSets.current(conversation.id).subgroup_id ==
               ParticipantSets.current(space.id).subgroup_id

      assert State.get(conversation.id, "cool.gravitas.river.context.v1")["content"] == metadata
      assert {:ok, _} = DelegatedGroups.membership(gc, conversation.id, %{"action" => "leave"})
      assert ParticipantSets.current(conversation.id).subgroup_id == pair.subgroup_id
      refute Contacts.connected?(a.id, b.id)
      assert {:ok, _} = RiverWorkspace.conversation(ga, params)

      assert {:error, :transaction_conflict} =
               RiverWorkspace.conversation(ga, Map.put(params, "context_id", conversation.id))

      # Removing a mathematical parent never mutates an independent conversation's roster.
      assert {:ok, _} = DelegatedGroups.membership(gb, space.id, %{"action" => "leave"})
      assert Memberships.joined?(conversation.id, b.id)
      assert State.get(conversation.id, "cool.gravitas.river.context.v1")["content"] == metadata
    end
  end

  test "multiple containing groups, equal sets, and hidden intermediate groups", %{
    people: [_, b, c, d],
    grants: [ga, gb, gc, gd]
  } do
    x = create(ga, "X")
    y = create(ga, "Y")
    pair = create(ga, "Pair")
    duplicate = create(ga, "Another-pair")
    for r <- [x, y, pair, duplicate], do: add(ga, gb, b, r)
    add(ga, gc, c, x)
    add(ga, gd, d, y)
    assert {:ok, view} = DelegatedGroups.subgroups(ga, pair.id)
    assert Enum.sort(Enum.map(view.parents, & &1.id)) == Enum.sort([x.id, y.id])
    assert Enum.any?(view.same_participant_groups, &(&1.id == duplicate.id))

    assert ParticipantSets.current(pair.id).subgroup_id ==
             ParticipantSets.current(duplicate.id).subgroup_id

    selected = %{ga | room_mode: :selected, room_ids: [pair.id, y.id]}
    assert {:ok, private} = DelegatedGroups.subgroups(selected, pair.id)
    assert Enum.map(private.containing_groups, & &1.id) == [y.id]
    assert private.same_participant_groups == []
    {:ok, token} = Tokens.issue(selected)
    conn = build_conn() |> put_req_header("authorization", "Bearer " <> token.access_token)
    assert get(conn, "/app/v1/groups/#{pair.id}/subgroups").status == 200
    assert {:error, :insufficient_scope} = DelegatedGroups.subgroups(%{ga | scopes: []}, pair.id)
  end

  test "group selection rejects outsiders and never widens selected consent", %{
    people: [_, b, _, outsider],
    grants: [ga, gb, _, gd]
  } do
    parent = create(ga, "Parent")
    add(ga, gb, b, parent)

    params = %{
      "name" => "Conversation",
      "member_ids" => [Identity.user_id(outsider.username)],
      "context_id" => parent.id,
      "txn_id" => "outsider"
    }

    assert {:error, :forbidden} = RiverWorkspace.conversation(ga, params)

    assert {:error, :forbidden} =
             RiverWorkspace.conversation(gd, %{
               params
               | "member_ids" => [Identity.user_id(b.username)]
             })

    assert {:error, :forbidden} =
             RiverWorkspace.conversation(%{ga | room_mode: :selected, room_ids: []}, params)

    assert {:error, :invalid_request} =
             RiverWorkspace.conversation(ga, Map.delete(params, "context_id"))
  end

  @tag native_graph: true
  test "federated group members can be selected without contacts and retain qualified identities", %{people: [a | _], grants: [ga | _]} do
    alias LakehouseMatrix.Federation.{RoomProtocol, Signing}
    alias LakehouseMatrix.Protocol.{Event, Graph}
    remote = "@peer:remote.org"
    seed = <<1::256>>
    lookup = fn server, "ed25519:test", _ ->
      if server == "remote.org", do: {:ok, Signing.public_key(seed)},
        else: {:ok, Signing.public_key(:binary.copy(<<7>>, 32))}
    end
    join = fn room ->
      {:ok, template} = RoomProtocol.make_membership("remote.org", room.room_id, remote, "join", ["12"])
      signed = Event.sign(template["event"], "12", seed, "ed25519:test", "remote.org")
      assert {:ok, _} = RoomProtocol.send_membership("remote.org", room.room_id, Event.id(signed, "12"), "join", signed, lookup)
    end
    parent = create(ga, "Federated")
    assert {:ok, _} = LakehouseMatrix.Matrix.invite(a.id, parent.room_id, remote)
    join.(parent)
    parent_set = ParticipantSets.current(parent.id).subgroup_id
    assert ParticipantSets.relations(parent_set).members == Enum.sort([ParticipantSets.principal(a.id), "matrix:" <> remote])
    assert {:ok, conversation} = RiverWorkspace.conversation(ga, %{
      "name" => "Remote subset", "member_ids" => [remote], "context_id" => parent.id, "txn_id" => "remote-subset"
    })
    assert State.get(conversation.id, "m.room.member", remote)["content"]["membership"] == "invite"
    assert Graph.room(conversation.id)
    join.(conversation)
    assert ParticipantSets.current(conversation.id).subgroup_id == parent_set
    before = ParticipantSets.current(conversation.id)
    LakehouseMatrix.Subgroups.backfill!()
    assert ParticipantSets.current(conversation.id) == before
    assert {:error, :forbidden} = RiverWorkspace.conversation(ga, %{
      "name" => "Stranger", "member_ids" => ["@outsider:remote.org"], "context_id" => parent.id, "txn_id" => "remote-stranger"
    })
  end

  @tag native_graph: true
  test "native Matrix membership follows the same registry", %{people: [a, b | _]} do
    {:ok, %{"room_id" => wire}} =
      LakehouseMatrix.ClientRooms.create(a.id, %{"name" => "Native", "preset" => "public_chat"})

    {:ok, local} = Identity.parse_room_id(wire)
    before = ParticipantSets.current(local)
    assert {:ok, _} = LakehouseMatrix.Matrix.join_room(b.id, wire)
    after_join = ParticipantSets.current(local)
    refute before.subgroup_id == after_join.subgroup_id
    assert {:ok, _} = LakehouseMatrix.Matrix.leave_room(b.id, wire)
    assert ParticipantSets.current(local).subgroup_id == before.subgroup_id
    assert Repo.aggregate(LakehouseIam.Schema.Principal, :count) >= 4
  end
end
