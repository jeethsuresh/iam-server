defmodule LakehouseWeb.Matrix.ProtocolCompatibilityTest do
  use LakehouseWeb.ConnCase, async: false
  import Ecto.Query
  alias LakehouseIam.{Repo, Apps.Grants}
  alias LakehouseMatrix.{DelegatedGroups, Identity, Matrix}
  alias LakehouseMatrix.Schema.RoomEvent
  alias LakehouseWeb.MatrixFixtures

  setup do
    alice = MatrixFixtures.user_fixture("protoalice")
    bob = MatrixFixtures.user_fixture("protobob")
    a = login(alice.username, "A")
    b = login(bob.username, "B")
    %{alice: alice, bob: bob, a: a, b: b}
  end

  defp login(name, device) do
    build_conn()
    |> post("/_matrix/client/v3/login", %{
      "type" => "m.login.password",
      "identifier" => %{"type" => "m.id.user", "user" => name},
      "password" => "password123",
      "device_id" => device
    })
    |> json_response(200)
  end

  defp api(session, method, path, data \\ %{}) do
    conn = build_conn() |> put_req_header("authorization", "Bearer " <> session["access_token"])
    Phoenix.ConnTest.dispatch(conn, @endpoint, method, path, data)
  end

  defp room(a) do
    api(a, :post, "/_matrix/client/v3/createRoom", %{"name" => "Native"})
    |> json_response(200)
    |> Map.fetch!("room_id")
  end

  defp sliding(a, body, query \\ "") do
    api(a, :post, "/_matrix/client/unstable/org.matrix.msc4186/sync" <> query, body)
  end

  defp list(limit \\ 10),
    do: %{
      "all" => %{
        "ranges" => [[0, 20]],
        "timeline_limit" => limit,
        "required_state" => [["*", "*"]]
      }
    }

  test "native relation routes and redactions through send use Matrix response semantics", %{
    a: a,
    alice: alice
  } do
    old = Application.get_env(:lakehouse_matrix, :signing_key)

    Application.put_env(
      :lakehouse_matrix,
      :signing_key,
      Base.encode64(<<0::256>>, padding: false)
    )

    on_exit(fn ->
      if is_nil(old),
        do: Application.delete_env(:lakehouse_matrix, :signing_key),
        else: Application.put_env(:lakehouse_matrix, :signing_key, old)
    end)

    {:ok, %{"room_id" => ref}} = LakehouseMatrix.Protocol.Rooms.create(alice.id, %{})
    summary = api(a, :get, "/_matrix/client/v1/room_summary/#{ref}") |> json_response(200)

    assert summary["room_id"] == ref and summary["room_version"] == "12" and
             summary["membership"] == "join"

    hierarchy = api(a, :get, "/_matrix/client/v1/rooms/#{ref}/hierarchy") |> json_response(200)
    assert [%{"room_id" => ^ref, "children_state" => []}] = hierarchy["rooms"]

    pushrules = api(a, :get, "/_matrix/client/v3/pushrules/") |> json_response(200)
    assert hd(pushrules["global"]["override"])["rule_id"] == ".m.rule.master"

    assert api(a, :put, "/_matrix/client/v3/pushrules/global/room/#{ref}", %{"actions" => []})
           |> json_response(200) == %{}

    assert api(a, :get, "/_matrix/client/v3/pushrules/global/room/#{ref}/actions")
           |> json_response(200) == %{"actions" => []}

    assert api(a, :get, "/_matrix/client/v3/notifications") |> json_response(200) == %{
             "notifications" => []
           }

    assert api(a, :get, "/_matrix/client/v3/pushers") |> json_response(200) == %{"pushers" => []}

    original =
      api(a, :put, "/_matrix/client/v3/rooms/#{ref}/send/m.room.message/original", %{
        "body" => "original"
      })
      |> json_response(200)

    event =
      api(a, :get, "/_matrix/client/v3/rooms/#{ref}/event/#{original["event_id"]}")
      |> json_response(200)

    timestamp =
      api(
        a,
        :get,
        "/_matrix/client/v1/rooms/#{ref}/timestamp_to_event?dir=f&ts=#{event["origin_server_ts"]}"
      )
      |> json_response(200)

    assert timestamp["origin_server_ts"] >= event["origin_server_ts"]

    assert api(a, :get, "/_matrix/client/v1/rooms/#{ref}/timestamp_to_event?dir=b")
           |> json_response(400)

    relation = %{
      "m.relates_to" => %{
        "rel_type" => "m.annotation",
        "event_id" => original["event_id"],
        "key" => "yes"
      }
    }

    first =
      api(a, :put, "/_matrix/client/v3/rooms/#{ref}/send/m.reaction/first", relation)
      |> json_response(200)

    duplicate =
      api(a, :put, "/_matrix/client/v3/rooms/#{ref}/send/m.reaction/second", relation)
      |> json_response(400)

    assert duplicate["errcode"] == "M_DUPLICATE_ANNOTATION"

    page =
      api(
        a,
        :get,
        "/_matrix/client/v1/rooms/#{ref}/relations/#{original["event_id"]}/m.annotation/m.reaction"
      )
      |> json_response(200)

    assert Enum.map(page["chunk"], & &1["event_id"]) == [first["event_id"]]

    assert api(a, :get, "/_matrix/client/v1/rooms/#{ref}/threads") |> json_response(200) == %{
             "chunk" => []
           }

    assert api(a, :put, "/_matrix/client/v3/rooms/#{ref}/send/m.room.redaction/missing", %{})
           |> json_response(400)

    assert api(a, :put, "/_matrix/client/v3/rooms/#{ref}/send/m.room.redaction/redact", %{
             "redacts" => first["event_id"]
           })
           |> json_response(200)

    page =
      api(a, :get, "/_matrix/client/v1/rooms/#{ref}/relations/#{original["event_id"]}")
      |> json_response(200)

    assert page["chunk"] == []

    replacement =
      api(a, :post, "/_matrix/client/v3/rooms/#{ref}/upgrade", %{"new_version" => "12"})
      |> json_response(200)
      |> Map.fetch!("replacement_room")

    create =
      api(a, :get, "/_matrix/client/v3/rooms/#{replacement}/state/m.room.create")
      |> json_response(200)

    assert create["predecessor"]["room_id"] == ref

    assert api(a, :post, "/_matrix/client/v3/rooms/#{ref}/upgrade", %{"new_version" => "unknown"})
           |> json_response(400)
           |> Map.fetch!("errcode") == "M_UNSUPPORTED_ROOM_VERSION"
  end

  test "sessions are device-specific, whoami works, and logout revokes only one device", %{
    a: a,
    alice: alice
  } do
    second = login(alice.username, "A2")
    assert a["access_token"] != second["access_token"]

    assert json_response(api(a, :get, "/_matrix/client/v3/account/whoami"), 200)["device_id"] ==
             "A"

    assert length(json_response(api(a, :get, "/_matrix/client/v3/devices"), 200)["devices"]) == 2
    assert json_response(api(a, :post, "/_matrix/client/v3/logout"), 200) == %{}

    assert json_response(api(a, :get, "/_matrix/client/v3/account/whoami"), 401)["errcode"] ==
             "M_UNKNOWN_TOKEN"

    assert json_response(api(second, :get, "/_matrix/client/v3/account/whoami"), 200)["device_id"] ==
             "A2"
  end

  test "full Matrix IDs log in, foreign IDs cannot alias local accounts", %{alice: alice} do
    assert login(Identity.user_id(alice.username), "MXID")["user_id"] ==
             Identity.user_id(alice.username)

    assert build_conn()
           |> post("/_matrix/client/v3/login", %{
             "user" => "@#{alice.username}:foreign.example",
             "password" => "password123"
           })
           |> json_response(403)
  end

  test "account data is private and incremental sync carries it", %{a: a, b: b, alice: alice} do
    initial = json_response(api(a, :get, "/_matrix/client/v3/sync"), 200)
    path = "/_matrix/client/v3/user/#{Identity.user_id(alice.username)}/account_data/m.direct"
    content = %{Identity.user_id("protobob") => ["!example:localhost"]}
    assert json_response(api(a, :put, path, content), 200) == %{}
    assert json_response(api(a, :get, path), 200) == content
    assert json_response(api(b, :get, path), 403)["errcode"] == "M_FORBIDDEN"

    delta =
      json_response(
        api(a, :get, "/_matrix/client/v3/sync", %{"since" => initial["next_batch"]}),
        200
      )

    assert delta["account_data"]["events"] == [%{"type" => "m.direct", "content" => content}]
  end

  test "same-timestamp and backdated events are not skipped by stream cursors", %{
    a: a,
    alice: alice
  } do
    ref = room(a)
    {:ok, id} = Identity.parse_room_id(ref)
    initial = json_response(api(a, :get, "/_matrix/client/v3/sync"), 200)

    for n <- 1..3 do
      {:ok, event} = Matrix.send_message(alice.id, id, "#{n}", %{"body" => "#{n}"})

      Repo.update_all(from(e in RoomEvent, where: e.event_id == ^event["event_id"]),
        set: [origin_server_ts: 1]
      )
    end

    delta =
      json_response(
        api(a, :get, "/_matrix/client/v3/sync", %{"since" => initial["next_batch"]}),
        200
      )

    assert Enum.map(delta["rooms"]["join"][ref]["timeline"]["events"], & &1["content"]["body"]) ==
             ~w(1 2 3)

    assert json_response(
             api(a, :get, "/_matrix/client/v3/sync", %{"since" => delta["next_batch"]}),
             200
           )["rooms"]["join"] == %{}
  end

  test "cursors cannot be reused by another user or device or forged", %{a: a, b: b, alice: alice} do
    initial = json_response(api(a, :get, "/_matrix/client/v3/sync"), 200)

    for session <- [b, login(alice.username, "OTHER")] do
      assert json_response(
               api(session, :get, "/_matrix/client/v3/sync", %{"since" => initial["next_batch"]}),
               400
             )["errcode"] == "M_INVALID_PARAM"
    end

    assert json_response(
             api(a, :get, "/_matrix/client/v3/sync", %{"since" => "s99999999999999999"}),
             400
           )
  end

  test "transaction retries are idempotent, and independent devices do not collide", %{
    a: a,
    alice: alice
  } do
    ref = room(a)
    path = "/_matrix/client/v3/rooms/#{ref}/send/m.room.message/retry"
    first = json_response(api(a, :put, path, %{"body" => "once"}), 200)
    assert json_response(api(a, :put, path, %{"body" => "ignored retry body"}), 200) == first
    other = login(alice.username, "OTHER")
    assert json_response(api(other, :put, path, %{"body" => "independent"}), 200) != first
    assert Repo.aggregate(from(e in RoomEvent, where: e.type == "m.room.message"), :count) == 2
  end

  test "River spaces and channel messages are visible and writable through standard APIs", %{
    a: a,
    alice: alice
  } do
    scopes =
      ~w(chats.list chats.read chats.write groups.create groups.manage groups.join spaces.channels)

    {:ok, g} = Grants.upsert(alice.id, "https://river.example", scopes, :all, [])

    {:ok, space} =
      DelegatedGroups.create(g, %{"name" => "River space", "kind" => "space", "txn_id" => "space"})

    {:ok, %{channels: [channel | _]}} = DelegatedGroups.channels(g, space.id)

    {:ok, event} =
      DelegatedGroups.send(g, channel.id, "m.room.message", "river-message", %{
        "body" => "From River"
      })

    sync = json_response(api(a, :get, "/_matrix/client/v3/sync"), 200)

    assert Enum.any?(
             sync["rooms"]["join"][channel.room_id]["timeline"]["events"],
             &(&1["event_id"] == event["event_id"])
           )

    state = json_response(api(a, :get, "/_matrix/client/v3/rooms/#{space.room_id}/state"), 200)

    assert Enum.any?(
             state,
             &(&1["type"] == "m.space.child" and &1["state_key"] == channel.room_id)
           )

    sent =
      json_response(
        api(a, :put, "/_matrix/client/v3/rooms/#{channel.room_id}/send/m.room.message/client", %{
          "body" => "From Matrix"
        }),
        200
      )

    {:ok, timeline} = DelegatedGroups.timeline(g, channel.id, %{})
    assert Enum.any?(timeline.events, &(&1["event_id"] == sent["event_id"]))
  end

  test "sliding windows return River rooms, requested state and later messages", %{a: a} do
    ref = room(a)
    initial = sliding(a, %{"lists" => list()}) |> json_response(200)
    assert initial["rooms"][ref]["initial"]
    assert initial["lists"]["all"]["count"] == 1
    assert Enum.any?(initial["rooms"][ref]["required_state"], &(&1["type"] == "m.room.create"))

    sent =
      json_response(
        api(a, :put, "/_matrix/client/v3/rooms/#{ref}/send/m.room.message/delta", %{
          "body" => "new"
        }),
        200
      )

    delta =
      sliding(a, %{}, "?" <> URI.encode_query(%{"pos" => initial["pos"]})) |> json_response(200)

    assert Enum.any?(delta["rooms"][ref]["timeline"], &(&1["event_id"] == sent["event_id"]))
    refute delta["rooms"][ref]["initial"]
  end

  test "subscriptions never expose unauthorized rooms, and positions are device-bound", %{
    a: a,
    b: b,
    alice: alice
  } do
    ref = room(a)

    request = %{
      "room_subscriptions" => %{
        ref => %{"timeline_limit" => 10, "required_state" => [["*", "*"]]}
      }
    }

    assert sliding(b, request) |> json_response(200) |> Map.fetch!("rooms") == %{}
    initial = sliding(a, %{"lists" => list()}) |> json_response(200)

    for session <- [b, login(alice.username, "A2")] do
      assert sliding(session, %{"pos" => initial["pos"]})
             |> json_response(400)
             |> Map.fetch!("errcode") == "M_UNKNOWN_POS"
    end
  end

  test "v4 proposal uses its current request and response state format", %{a: a} do
    ref = room(a)

    body = %{
      "lists" => %{
        "all" => %{
          "range" => [0, 20],
          "timeline_limit" => 2,
          "required_state" => %{"include" => [%{"type" => "m.room.create"}]}
        }
      }
    }

    first = api(a, :post, "/_matrix/client/v4/sync", body) |> json_response(200)
    assert [%{"type" => "m.room.create"}] = first["rooms"][ref]["required_state"]

    second =
      api(a, :post, "/_matrix/client/v4/sync", %{"pos" => first["pos"]}) |> json_response(200)

    assert second["rooms"] == %{}
  end

  test "invites have stripped state and no timeline before acceptance", %{a: a, b: b} do
    ref = room(a)

    json_response(
      api(a, :post, "/_matrix/client/v3/rooms/#{ref}/invite", %{"user_id" => b["user_id"]}),
      200
    )

    sync = sliding(b, %{"lists" => list()}) |> json_response(200)
    assert sync["rooms"][ref]["membership"] == "invite"
    refute Map.has_key?(sync["rooms"][ref], "timeline")

    assert Enum.all?(
             sync["rooms"][ref]["invite_state"],
             &(Map.keys(&1) -- ~w(type state_key content sender) == [])
           )
  end

  test "to-device messages survive retries, isolate devices and are acknowledged by sync", %{
    a: a,
    b: b,
    bob: bob
  } do
    other = login(bob.username, "B2")
    content = %{"messages" => %{b["user_id"] => %{"B" => %{"secret" => "for B only"}}}}
    path = "/_matrix/client/v3/sendToDevice/m.test/once"
    assert json_response(api(a, :put, path, content), 200) == %{}
    assert json_response(api(a, :put, path, content), 200) == %{}
    one = json_response(api(b, :get, "/_matrix/client/v3/sync"), 200)
    assert [%{"content" => %{"secret" => "for B only"}}] = one["to_device"]["events"]

    assert json_response(api(other, :get, "/_matrix/client/v3/sync"), 200)["to_device"]["events"] ==
             []

    assert json_response(
             api(b, :get, "/_matrix/client/v3/sync", %{"since" => one["next_batch"]}),
             200
           )["to_device"]["events"] == []
  end

  test "one-time keys are claimed once and device keys cannot impersonate another device", %{a: a} do
    keys = %{
      "user_id" => a["user_id"],
      "device_id" => "A",
      "algorithms" => ["m.olm.v1.curve25519-aes-sha2"],
      "keys" => %{"ed25519:A" => "public"}
    }

    upload = %{
      "device_keys" => keys,
      "one_time_keys" => %{"signed_curve25519:one" => %{"key" => "one"}}
    }

    assert json_response(api(a, :post, "/_matrix/client/v3/keys/upload", upload), 200)[
             "one_time_key_counts"
           ] == %{"signed_curve25519" => 1}

    query = %{"one_time_keys" => %{a["user_id"] => %{"A" => "signed_curve25519"}}}

    assert json_response(api(a, :post, "/_matrix/client/v3/keys/claim", query), 200)[
             "one_time_keys"
           ][a["user_id"]]["A"] == %{"signed_curve25519:one" => %{"key" => "one"}}

    refute Map.has_key?(
             json_response(api(a, :post, "/_matrix/client/v3/keys/claim", query), 200)[
               "one_time_keys"
             ][a["user_id"]],
             "A"
           )

    assert json_response(
             api(a, :post, "/_matrix/client/v3/keys/upload", %{
               "device_keys" => Map.put(keys, "device_id", "OTHER")
             }),
             400
           )
  end

  test "history paginates without duplicate events and rejects foreign domains", %{a: a} do
    ref = room(a)

    for n <- 1..5,
        do:
          json_response(
            api(a, :put, "/_matrix/client/v3/rooms/#{ref}/send/m.room.message/#{n}", %{
              "body" => "#{n}"
            }),
            200
          )

    path = "/_matrix/client/v3/rooms/#{ref}/messages"
    first = json_response(api(a, :get, path, %{"limit" => 3, "dir" => "b"}), 200)

    second =
      json_response(
        api(a, :get, path, %{"limit" => 3, "dir" => "b", "from" => first["end"]}),
        200
      )

    one = Enum.map(first["chunk"], & &1["event_id"])
    two = Enum.map(second["chunk"], & &1["event_id"])
    assert MapSet.disjoint?(MapSet.new(one), MapSet.new(two))
    foreign = String.replace(ref, ":localhost", ":foreign.example")
    assert json_response(api(a, :get, "/_matrix/client/v3/rooms/#{foreign}/state"), 403)
  end

  test "redactions remove client-visible content, including paginated history", %{a: a} do
    ref = room(a)

    event =
      json_response(
        api(a, :put, "/_matrix/client/v3/rooms/#{ref}/send/m.room.message/secret", %{
          "body" => "delete me"
        }),
        200
      )["event_id"]

    json_response(
      api(a, :put, "/_matrix/client/v3/rooms/#{ref}/redact/#{event}/delete", %{}),
      200
    )

    assert json_response(api(a, :get, "/_matrix/client/v3/rooms/#{ref}/event/#{event}"), 200)[
             "content"
           ] == %{}
  end

  test "Matrix CORS supports browser clients and unknown endpoints return Matrix errors" do
    conn = build_conn() |> options("/_matrix/client/v3/sync")
    assert conn.status == 204
    assert get_resp_header(conn, "access-control-allow-origin") == ["*"]
    assert get_resp_header(conn, "access-control-allow-methods") |> hd() =~ "PUT"

    assert build_conn() |> get("/_matrix/unknown") |> json_response(404) |> Map.fetch!("errcode") ==
             "M_UNRECOGNIZED"
  end

  test "private rooms require an invite and creation honors encryption initial state", %{
    a: a,
    b: b
  } do
    encrypted = %{
      "type" => "m.room.encryption",
      "state_key" => "",
      "content" => %{"algorithm" => "m.megolm.v1.aes-sha2"}
    }

    ref =
      api(a, :post, "/_matrix/client/v3/createRoom", %{"initial_state" => [encrypted]})
      |> json_response(200)
      |> Map.fetch!("room_id")

    assert api(b, :post, "/_matrix/client/v3/join/#{ref}") |> json_response(403)

    assert api(a, :get, "/_matrix/client/v3/rooms/#{ref}/state/m.room.encryption")
           |> json_response(200) == encrypted["content"]

    json_response(
      api(a, :post, "/_matrix/client/v3/rooms/#{ref}/invite", %{"user_id" => b["user_id"]}),
      200
    )

    assert api(b, :post, "/_matrix/client/v3/join/#{ref}") |> json_response(200)
  end

  test "joined history visibility is enforced in sync, history, direct reads and sliding sync", %{
    a: a,
    b: b
  } do
    ref = room(a)

    json_response(
      api(a, :put, "/_matrix/client/v3/rooms/#{ref}/state/m.room.history_visibility", %{
        "history_visibility" => "joined"
      }),
      200
    )

    hidden =
      api(a, :put, "/_matrix/client/v3/rooms/#{ref}/send/m.room.message/before", %{
        "body" => "before join"
      })
      |> json_response(200)
      |> Map.fetch!("event_id")

    json_response(
      api(a, :post, "/_matrix/client/v3/rooms/#{ref}/invite", %{"user_id" => b["user_id"]}),
      200
    )

    json_response(api(b, :post, "/_matrix/client/v3/join/#{ref}"), 200)

    visible =
      api(a, :put, "/_matrix/client/v3/rooms/#{ref}/send/m.room.message/after", %{
        "body" => "after join"
      })
      |> json_response(200)
      |> Map.fetch!("event_id")

    ordinary = api(b, :get, "/_matrix/client/v3/sync") |> json_response(200)
    history = api(b, :get, "/_matrix/client/v3/rooms/#{ref}/messages") |> json_response(200)
    window = sliding(b, %{"lists" => list()}) |> json_response(200)

    for events <- [
          ordinary["rooms"]["join"][ref]["timeline"]["events"],
          history["chunk"],
          window["rooms"][ref]["timeline"]
        ] do
      refute Enum.any?(events, &(&1["event_id"] == hidden))
      assert Enum.any?(events, &(&1["event_id"] == visible))
    end

    assert api(b, :get, "/_matrix/client/v3/rooms/#{ref}/event/#{hidden}") |> json_response(404)
  end

  test "enabling to-device after room sync preserves messages and uses its own acknowledged cursor",
       %{a: a, b: b} do
    json_response(
      api(a, :put, "/_matrix/client/v3/sendToDevice/m.test/queued", %{
        "messages" => %{b["user_id"] => %{"B" => %{"secret" => "retained"}}}
      }),
      200
    )

    first = sliding(b, %{}) |> json_response(200)
    second = sliding(b, %{"pos" => first["pos"]}) |> json_response(200)

    enabled =
      sliding(b, %{"pos" => second["pos"], "extensions" => %{"to_device" => %{"enabled" => true}}})
      |> json_response(200)

    assert [%{"content" => %{"secret" => "retained"}}] =
             enabled["extensions"]["to_device"]["events"]

    retry =
      sliding(b, %{"pos" => second["pos"], "extensions" => %{"to_device" => %{"enabled" => true}}})
      |> json_response(200)

    assert retry["extensions"]["to_device"]["events"] ==
             enabled["extensions"]["to_device"]["events"]

    acknowledged =
      sliding(b, %{
        "pos" => enabled["pos"],
        "extensions" => %{
          "to_device" => %{
            "enabled" => true,
            "since" => enabled["extensions"]["to_device"]["next_batch"]
          }
        }
      })
      |> json_response(200)

    assert acknowledged["extensions"]["to_device"]["events"] == []
  end

  test "room account data extensions include updates even without new room events", %{a: a} do
    ref = room(a)
    request = %{"lists" => list(), "extensions" => %{"account_data" => %{"enabled" => true}}}
    first = sliding(a, request) |> json_response(200)
    path = "/_matrix/client/v3/user/#{a["user_id"]}/rooms/#{ref}/account_data/m.tag"
    json_response(api(a, :put, path, %{"tags" => %{"m.favourite" => %{}}}), 200)
    second = sliding(a, %{"pos" => first["pos"]}) |> json_response(200)
    assert [%{"type" => "m.tag"}] = second["extensions"]["account_data"]["rooms"][ref]
  end

  test "malformed sliding and login parameters return errors instead of raising", %{a: a} do
    for config <- [
          %{"ranges" => 42},
          %{"range" => [2, 1]},
          %{"required_state" => 42},
          %{"filters" => %{"spaces" => 42}}
        ] do
      assert sliding(a, %{"lists" => %{"bad" => config}}) |> json_response(400)
    end

    assert build_conn()
           |> post("/_matrix/client/v3/login", %{"identifier" => [], "password" => "password123"})
           |> json_response(400)
  end
end
