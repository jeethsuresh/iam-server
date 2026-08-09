defmodule LakehouseMatrix.Events.ProcessorTest do
  use LakehouseMatrix.DataCase, async: true

  alias LakehouseIam.IAM
  alias LakehouseMatrix.Events.Context
  alias LakehouseMatrix.Events.Processor
  alias LakehouseMatrix.{Events, Memberships, Rooms}
  alias LakehouseMatrix.Fixtures

  setup do
    principal = Fixtures.user_fixture("procuser")
    _ = IAM.assign_role(principal.id, "member")
    {:ok, principal: principal}
  end

  test "processes m.room.message and persists timeline event", %{principal: principal} do
    {:ok, room} = Rooms.create_room_record(%{name: "Test"})
    _ = Rooms.ensure_started(room.id)

    join_ctx = %Context{
      room_id: room.id,
      principal_id: principal.id,
      sender: "@procuser:localhost",
      event_id: "$join",
      type: "m.room.member",
      content: %{"membership" => "join", "displayname" => "procuser"},
      state_key: "@procuser:localhost",
      origin_server_ts: 1
    }

    Memberships.upsert_membership(room.id, principal.id, "join", join_ctx)

    ctx = %Context{
      room_id: room.id,
      principal_id: principal.id,
      sender: "@procuser:localhost",
      event_id: "$evt1",
      type: "m.room.message",
      content: %{"body" => "hi", "msgtype" => "m.text"},
      state_key: nil,
      origin_server_ts: System.system_time(:millisecond)
    }

    assert {:ok, event} = Processor.process(ctx)
    assert event["type"] == "m.room.message"
    assert Events.list_timeline(room.id) |> length() == 1
  end

  test "rejects unsupported event types", %{principal: principal} do
    {:ok, room} = Rooms.create_room_record(%{name: "Test"})

    ctx = %Context{
      room_id: room.id,
      principal_id: principal.id,
      sender: "@procuser:localhost",
      event_id: "$evt2",
      type: "m.reaction",
      content: %{},
      state_key: nil,
      origin_server_ts: 1
    }

    assert {:error, {:unsupported_event, "m.reaction"}} = Processor.process(ctx)
  end
end
