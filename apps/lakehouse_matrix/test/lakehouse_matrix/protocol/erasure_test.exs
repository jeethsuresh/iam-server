defmodule LakehouseMatrix.ErasureTest do
  use LakehouseMatrix.DataCase, async: false
  alias LakehouseMatrix.{ClientRooms, Erasure, Events, Fixtures, Identity, Matrix}
  alias LakehouseMatrix.Protocol.{Event, Graph}
  alias LakehouseMatrix.Schema.RoomEvent

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

    author = Fixtures.user_fixture("author")
    before = Fixtures.user_fixture("before")
    later = Fixtures.user_fixture("later")
    {:ok, %{"room_id" => ref}} = ClientRooms.create(author.id, %{"preset" => "public_chat"})
    {:ok, _} = Matrix.join_room(before.id, ref)
    {:ok, local} = Identity.parse_room_id(ref)
    sender = Identity.user_id(author.username)

    {:ok, event} =
      Graph.send(local, sender, "m.room.message", %{
        "body" => "Original private history",
        "msgtype" => "m.text"
      })

    %{
      author: author,
      before: before,
      later: later,
      local: local,
      ref: ref,
      sender: sender,
      event: event
    }
  end

  test "erasure defaults to pruned storage and preserves original copies only for prior members",
       c do
    assert {:ok, :ok} = Repo.transaction(fn -> Erasure.erase!(c.author.id) end)
    record = Repo.get_by!(RoomEvent, event_id: c.event["event_id"])
    assert record.content == %{}
    assert Graph.event(record.event_id).pdu["content"]["body"] == "Original private history"
    assert Event.id(Graph.event(record.event_id).pdu, "12") == record.event_id
    assert {:ok, _} = Matrix.join_room(c.later.id, c.ref)
    raw = Events.to_client_event(record)
    assert Erasure.client(raw, c.before.id)["content"]["body"] == "Original private history"
    assert Erasure.client(raw, c.later.id)["content"] == %{}
    assert Erasure.client(raw, :anonymous)["content"] == %{}

    assert Erasure.original(record.event_id, {:server, Identity.homeserver_domain()}).pdu[
             "content"
           ]["body"] == "Original private history"

    assert Erasure.federation(record.event_id, "new.example.org", c.event)["content"] == %{}

    assert Repo.one(
             from e in Erasure.event_query(c.before.id),
               where: e.event_id == ^record.event_id,
               select: e.content
           )["body"] == "Original private history"

    assert Repo.one(
             from e in Erasure.event_query(c.later.id),
               where: e.event_id == ^record.event_id,
               select: e.content
           ) == %{}

    assert Repo.one(
             from e in Erasure.pdu_query(c.before.id),
               where: e.event_id == ^record.event_id,
               select: e.pdu
           )["content"]["body"] == "Original private history"

    assert {:ok, visible} = ClientRooms.event(c.before.id, c.ref, record.event_id)
    assert visible["content"]["body"] == "Original private history"
    assert {:ok, hidden} = ClientRooms.event(c.later.id, c.ref, record.event_id)
    assert hidden["content"] == %{}
    assert {:ok, old_sync} = LakehouseMatrix.ClientSync.sync(c.before.id, "B", %{})

    assert Enum.any?(
             old_sync["rooms"]["join"][c.ref]["timeline"]["events"],
             &(&1["content"]["body"] == "Original private history")
           )

    assert {:ok, new_sync} = LakehouseMatrix.ClientSync.sync(c.later.id, "L", %{})

    refute Enum.any?(
             new_sync["rooms"]["join"][c.ref]["timeline"]["events"],
             &(&1["content"]["body"] == "Original private history")
           )

    assert {:ok, :ok} = Repo.transaction(fn -> Erasure.erase!(c.author.id) end)
    assert Erasure.client(raw, c.before.id)["content"]["body"] == "Original private history"
  end

  test "real redaction supersedes preserved originals", c do
    assert {:ok, :ok} = Repo.transaction(fn -> Erasure.erase!(c.author.id) end)

    assert {:ok, _} =
             ClientRooms.redact(c.author.id, "D", c.ref, c.event["event_id"], "redact", %{})

    raw = Events.to_client_event(Repo.get_by!(RoomEvent, event_id: c.event["event_id"]))
    assert Erasure.client(raw, c.before.id)["content"] == %{}
    assert Erasure.original(c.event["event_id"], {:user, c.before.id}) == nil

    assert Erasure.federation(c.event["event_id"], Identity.homeserver_domain(), c.event)[
             "content"
           ] == %{}
  end

  test "search and relation indexes restore prior copies without exposing erased content to later joiners",
       c do
    alias LakehouseMatrix.{ClientRelations, ClientSearch}

    {:ok, root} =
      Graph.send(c.local, Identity.user_id(c.before.username), "m.room.message", %{
        "body" => "Other person's root",
        "msgtype" => "m.text"
      })

    {:ok, reaction} =
      Graph.send(c.local, c.sender, "m.reaction", %{
        "m.relates_to" => %{
          "rel_type" => "m.annotation",
          "event_id" => root["event_id"],
          "key" => "private reaction"
        }
      })

    {:ok, edit} =
      Graph.send(c.local, c.sender, "m.room.message", %{
        "msgtype" => "m.text",
        "body" => "secret edited text",
        "m.new_content" => %{"msgtype" => "m.text", "body" => "secret edited text"},
        "m.relates_to" => %{"rel_type" => "m.replace", "event_id" => c.event["event_id"]}
      })

    assert {:ok, :ok} = Repo.transaction(fn -> Erasure.erase!(c.author.id) end)
    assert {:ok, _} = Matrix.join_room(c.later.id, c.ref)

    criteria = %{
      "search_categories" => %{
        "room_events" => %{
          "search_term" => "Original",
          "event_context" => %{"include_profile" => true},
          "include_state" => true
        }
      }
    }

    assert {:ok, found} = ClientSearch.search(c.before.id, "B", criteria)

    assert Enum.any?(
             found["search_categories"]["room_events"]["results"],
             &(&1["result"]["event_id"] == c.event["event_id"])
           )

    assert {:ok, hidden} = ClientSearch.search(c.later.id, "L", criteria)
    assert hidden["search_categories"]["room_events"]["results"] == []

    for recurse <- [false, true] do
      assert {:ok, old_relations} =
               ClientRelations.page(c.before.id, "B", c.ref, root["event_id"], %{
                 "recurse" => recurse
               })

      assert Enum.any?(old_relations["chunk"], &(&1["event_id"] == reaction["event_id"]))

      assert {:ok, new_relations} =
               ClientRelations.page(c.later.id, "L", c.ref, root["event_id"], %{
                 "recurse" => recurse
               })

      assert new_relations["chunk"] == []
    end

    assert {:ok, old_event} = ClientRooms.event(c.before.id, c.ref, c.event["event_id"])

    assert get_in(old_event, ["unsigned", "m.relations", "m.replace", "event_id"]) ==
             edit["event_id"]

    assert {:ok, new_event} = ClientRooms.event(c.later.id, c.ref, c.event["event_id"])
    refute get_in(new_event, ["unsigned", "m.relations", "m.replace"])
  end

  test "erasure keeps canonical ACL policy intact and does not synthesize redaction events", c do
    {:ok, acl} =
      Graph.send(
        c.local,
        c.sender,
        "m.room.server_acl",
        %{"allow" => ["*"], "deny" => ["evil.example.org"]},
        ""
      )

    before = Repo.aggregate(from(e in RoomEvent, where: e.type == "m.room.redaction"), :count)
    assert {:ok, :ok} = Repo.transaction(fn -> Erasure.erase!(c.author.id) end)
    assert Graph.event(acl["event_id"]).pdu["content"]["deny"] == ["evil.example.org"]
    refute LakehouseMatrix.Federation.RoomAccess.allowed?(Graph.room(c.local), "evil.example.org")

    assert Repo.aggregate(from(e in RoomEvent, where: e.type == "m.room.redaction"), :count) ==
             before

    assert {:ok, _} = Matrix.join_room(c.later.id, c.ref)
    assert {:ok, original} = ClientRooms.event(c.before.id, c.ref, acl["event_id"])
    assert original["content"]["deny"] == ["evil.example.org"]
    assert {:ok, pruned} = ClientRooms.event(c.later.id, c.ref, acl["event_id"])
    assert pruned["content"] == %{}
  end

  test "federation event, state and backfill views and queued delivery respect prior server membership",
       c do
    alias LakehouseMatrix.Federation.RoomProtocol

    {:ok, name} =
      Graph.send(c.local, c.sender, "m.room.name", %{"name" => "Private room name"}, "")

    {:ok, _} =
      Graph.send(
        c.local,
        c.sender,
        "m.room.history_visibility",
        %{"history_visibility" => "world_readable"},
        ""
      )

    {:ok, public} =
      Graph.send(c.local, c.sender, "m.room.message", %{"body" => "Erased public text"})

    assert {:ok, :ok} = Repo.transaction(fn -> Erasure.erase!(c.author.id) end)
    old = Identity.homeserver_domain()
    fresh = "new.example.org"
    assert {:ok, %{"pdus" => [original]}} = RoomProtocol.event(old, public["event_id"])
    assert original["content"]["body"] == "Erased public text"
    assert {:ok, %{"pdus" => [pruned]}} = RoomProtocol.event(fresh, public["event_id"])
    assert pruned["content"] == %{}
    assert Event.id(pruned, "12") == public["event_id"]
    assert {:ok, new_state} = RoomProtocol.state(fresh, c.ref, public["event_id"])

    assert Enum.find(new_state["pdus"], &(Event.id(&1, "12") == name["event_id"]))["content"] ==
             %{}

    assert {:ok, old_state} = RoomProtocol.state(old, c.ref, public["event_id"])

    assert Enum.find(old_state["pdus"], &(Event.id(&1, "12") == name["event_id"]))["content"][
             "name"
           ] == "Private room name"

    {:ok, after_event} =
      Graph.send(c.local, Identity.user_id(c.before.username), "m.room.message", %{
        "body" => "Later root"
      })

    assert {:ok, backfill} = RoomProtocol.backfill(fresh, c.ref, [after_event["event_id"]], 20)

    assert Enum.find(backfill["pdus"], &(Event.id(&1, "12") == public["event_id"]))["content"] ==
             %{}

    item = %{
      kind: "pdu",
      event_id: public["event_id"],
      destination: fresh,
      payload: %{"pdus" => [public]}
    }

    assert Erasure.outbox(item)["pdus"] |> hd() |> Map.fetch!("content") == %{}

    assert Erasure.outbox(%{item | destination: old})["pdus"]
           |> hd()
           |> Map.fetch!("content")
           |> Map.fetch!("body") == "Erased public text"

    stripped = [
      %{
        "type" => "m.room.name",
        "state_key" => "",
        "sender" => c.sender,
        "content" => %{"name" => "Private room name"}
      }
    ]

    assert hd(Erasure.stripped(stripped, c.local, {:user, c.later.id}, "12"))["content"] == %{}

    assert hd(Erasure.stripped(stripped, c.local, {:user, c.before.id}, "12"))["content"]["name"] ==
             "Private room name"
  end

  test "late history and auth-chain outliers from an erased author retain the same presentation boundary",
       c do
    assert {:ok, :ok} = Repo.transaction(fn -> Erasure.erase!(c.author.id) end)
    {:ok, _} = Matrix.join_room(c.later.id, c.ref)
    {:ok, late} = Graph.send(c.local, c.sender, "m.room.message", %{"body" => "Late history"})
    assert Repo.get_by!(RoomEvent, event_id: late["event_id"]).content == %{}
    assert {:ok, original} = ClientRooms.event(c.before.id, c.ref, late["event_id"])
    assert original["content"]["body"] == "Late history"
    assert {:ok, pruned} = ClientRooms.event(c.later.id, c.ref, late["event_id"])
    assert pruned["content"] == %{}

    {:ok, late_name} =
      Graph.send(c.local, c.sender, "m.room.name", %{"name" => "Late private name"}, "")

    assert Repo.get!(LakehouseMatrix.Schema.Room, c.local).name == ""
    assert {:ok, prior_name} = ClientRooms.event(c.before.id, c.ref, late_name["event_id"])
    assert prior_name["content"] == %{"name" => "Late private name"}
    assert {:ok, later_name} = ClientRooms.event(c.later.id, c.ref, late_name["event_id"])
    assert later_name["content"] == %{}
    metadata = Graph.room(c.local)
    graph = Graph.load_graph(c.local)

    wire =
      Graph.template(
        metadata,
        graph,
        c.sender,
        "m.room.message",
        %{"body" => "Auth-only history"},
        nil
      )
      |> Event.sign("12", <<0::256>>, "ed25519:test", Identity.homeserver_domain())

    id = Event.id(wire, "12")

    snapshot = %{
      create: Map.put(Graph.event(metadata.create_id).pdu, "event_id", metadata.create_id),
      event: c.event,
      graph: Map.put(graph, id, Map.put(wire, "event_id", id))
    }

    assert {:ok, :ok} = Graph.store_auth(c.local, snapshot)
    assert Graph.event(id).outlier
    assert Erasure.pdu(Graph.event(id), c.before.id).pdu["content"]["body"] == "Auth-only history"
    assert Erasure.pdu(Graph.event(id), c.later.id).pdu["content"] == %{}
  end

  test "River attachment listings use the same erasure and redaction view as their source events",
       c do
    file = %{
      "id" => Ecto.UUID.generate(),
      "name" => "Private notes.txt",
      "size" => 20,
      "mime" => "text/plain",
      "sha256" => String.duplicate("a", 64),
      "scope" => "room",
      "targetId" => c.local
    }

    {:ok, source} =
      Graph.send(c.local, c.sender, "m.room.message", %{
        "body" => "Notes",
        "cool.gravitas.river.attachments" => [file]
      })

    Repo.insert!(%LakehouseMatrix.Schema.RiverFile{
      id: file["id"],
      room_id: c.local,
      uploader_id: c.author.id,
      event_id: source["event_id"],
      manifest: file
    })

    {:ok, prior} =
      LakehouseIam.Apps.Grants.upsert(
        c.before.id,
        "https://chat.gravitas.cool",
        ["chats.read"],
        :all,
        []
      )

    {:ok, fresh} =
      LakehouseIam.Apps.Grants.upsert(
        c.later.id,
        "https://chat.gravitas.cool",
        ["chats.read"],
        :all,
        []
      )

    assert {:ok, :ok} = Repo.transaction(fn -> Erasure.erase!(c.author.id) end)
    {:ok, _} = Matrix.join_room(c.later.id, c.ref)
    assert {:ok, %{attachments: [^file]}} = LakehouseMatrix.RiverFiles.list(prior, c.local, %{})

    assert {:ok, %{attachment: ^file}} =
             LakehouseMatrix.RiverFiles.list(prior, c.local, %{"file_id" => file["id"]})

    assert {:ok, %{attachments: []}} = LakehouseMatrix.RiverFiles.list(fresh, c.local, %{})

    assert {:error, :not_found} =
             LakehouseMatrix.RiverFiles.list(fresh, c.local, %{"file_id" => file["id"]})

    assert {:ok, _} =
             ClientRooms.redact(c.author.id, "A", c.ref, source["event_id"], "erase-file", %{})

    assert {:ok, %{attachments: []}} = LakehouseMatrix.RiverFiles.list(prior, c.local, %{})
  end

  test "River read models restore prior edits, replies and reactions while hiding erased content from later members",
       c do
    {:ok, %{"room_id" => space_ref}} =
      ClientRooms.create(c.author.id, %{
        "preset" => "public_chat",
        "creation_content" => %{"type" => "m.space"}
      })
    {:ok, _} = Matrix.join_room(c.before.id, space_ref)
    {:ok, space} = Identity.parse_room_id(space_ref)
    c = %{c | local: space, ref: space_ref}

    {:ok, post} =
      Graph.send(c.local, c.sender, "cool.gravitas.river.post.v1", %{
        "version" => 1,
        "title" => "Old title",
        "body" => "Old body"
      })

    {:ok, _} =
      Graph.send(c.local, c.sender, "cool.gravitas.river.entry.edit.v1", %{
        "m.relates_to" => %{"event_id" => post["event_id"], "rel_type" => "m.replace"},
        "m.new_content" => %{"title" => "Edited title", "body" => "Edited body"}
      })

    {:ok, _} =
      Graph.send(c.local, c.sender, "m.reaction", %{
        "m.relates_to" => %{
          "event_id" => post["event_id"],
          "rel_type" => "m.annotation",
          "key" => "👍"
        }
      })

    {:ok, _} =
      Graph.send(c.local, c.sender, "m.room.message", %{
        "body" => "Reply",
        "m.relates_to" => %{"event_id" => post["event_id"], "rel_type" => "m.thread"}
      })

    assert {:ok, :ok} = Repo.transaction(fn -> Erasure.erase!(c.author.id) end)
    {:ok, _} = Matrix.join_room(c.later.id, c.ref)
    row = Repo.get_by!(RoomEvent, event_id: post["event_id"])
    [old] = LakehouseMatrix.RiverContent.decorate([row], c.before.id)
    assert old["content"]["body"] == "Old body"
    assert old["rendered_content"]["body"] == "Edited body"
    assert old["reply_count"] == 1
    assert [%{key: "👍", count: 1}] = old["reaction_summary"]
    [fresh] = LakehouseMatrix.RiverContent.decorate([row], c.later.id)
    assert fresh["content"] == %{}
    refute fresh["edited"]
    assert fresh["reply_count"] == 0
    assert fresh["reaction_summary"] == []
  end
end
