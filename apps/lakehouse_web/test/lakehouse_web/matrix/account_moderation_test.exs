defmodule LakehouseWeb.Matrix.AccountModerationTest do
  use LakehouseWeb.ConnCase, async: false
  alias LakehouseWeb.MatrixFixtures

  alias LakehouseMatrix.{
    AccountModeration,
    ClientLogin,
    ClientProfiles,
    ClientRooms,
    Identity,
    Matrix
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

    admin =
      case LakehouseIam.Accounts.fetch_user("admin") do
        {:ok, account} -> account
        :error -> MatrixFixtures.user_fixture("admin")
      end

    user = MatrixFixtures.user_fixture("moduser")
    other = MatrixFixtures.user_fixture("modother")
    {:ok, session} = ClientLogin.open(user, %{"refresh_token" => true})
    {:ok, admin_session} = ClientLogin.open(admin, %{})
    {:ok, %{"room_id" => ref}} = ClientRooms.create(user.id, %{"preset" => "public_chat"})
    {:ok, _} = Matrix.join_room(other.id, ref)
    {:ok, room} = ClientRooms.room(ref)

    %{
      admin: admin,
      user: user,
      other: other,
      session: session,
      admin_session: admin_session,
      ref: ref,
      room: room.id,
      mxid: Identity.user_id(user.username)
    }
  end

  defp api(session, method, path, body \\ %{}) do
    conn = build_conn() |> put_req_header("authorization", "Bearer " <> session["access_token"])
    Phoenix.ConnTest.dispatch(conn, @endpoint, method, "/_matrix/client" <> path, body)
  end

  test "administration authorizes before account lookup, validates booleans and refuses self moderation",
       c do
    for path <- ["/v1/admin/lock/", "/v1/admin/suspend/"] do
      for user <- [c.mxid, "@absent:example.org"] do
        assert api(c.session, :get, path <> URI.encode(user))
               |> json_response(403)
               |> Map.fetch!("errcode") == "M_FORBIDDEN"
      end
    end

    assert api(c.admin_session, :put, "/v1/admin/lock/" <> URI.encode(c.mxid), %{
             "locked" => "true"
           })
           |> json_response(400)
           |> Map.fetch!("errcode") == "M_INVALID_PARAM"

    assert api(
             c.admin_session,
             :put,
             "/v1/admin/lock/" <> URI.encode(Identity.user_id("admin")),
             %{"locked" => true}
           )
           |> json_response(403)
           |> Map.fetch!("errcode") == "M_FORBIDDEN"

    assert api(c.admin_session, :get, "/v1/admin/lock/" <> URI.encode(c.mxid))
           |> json_response(200) == %{"locked" => false}
  end

  test "locking retains sessions, covers legacy tokens, refresh and public authenticated requests, and is reversible",
       c do
    legacy = LakehouseIam.Auth.Token.issue(c.user.username)

    assert api(c.admin_session, :put, "/v1/admin/lock/" <> URI.encode(c.mxid), %{"locked" => true})
           |> json_response(200) == %{"locked" => true}

    for token <- [c.session, %{"access_token" => legacy}],
        path <- [
          "/v3/account/whoami",
          "/v3/sync",
          "/versions",
          "/v3/profile/" <> URI.encode(c.mxid)
        ] do
      assert api(token, :get, path) |> json_response(401) == %{
               "errcode" => "M_USER_LOCKED",
               "error" => "This account has been locked",
               "soft_logout" => true
             }
    end

    assert {:error, :user_locked} = ClientLogin.refresh(c.session["refresh_token"])
    assert {:error, :user_locked} = ClientLogin.open(c.user, %{})

    assert {:error, :user_locked} =
             Graph.send(c.room, c.mxid, "m.room.message", %{"body" => "blocked"})

    assert {:ok, _} = AccountModeration.admin(c.admin.id, c.mxid, :matrix_locked, false)

    assert api(c.session, :get, "/v3/account/whoami")
           |> json_response(200)
           |> Map.fetch!("user_id") == c.mxid

    assert {:ok, _} = ClientLogin.refresh(c.session["refresh_token"])
  end

  test "locked clients can still log out and invalidate their credentials", c do
    assert {:ok, _} = AccountModeration.admin(c.admin.id, c.mxid, :matrix_locked, true)
    assert api(c.session, :post, "/v3/logout") |> json_response(200) == %{}

    assert api(c.session, :get, "/v3/account/whoami")
           |> json_response(401)
           |> Map.fetch!("errcode") == "M_UNKNOWN_TOKEN"
  end

  test "suspension permits reads, login, encryption recovery, own redaction and leaving but prevents room and profile writes",
       c do
    {:ok, own} = Graph.send(c.room, c.mxid, "m.room.message", %{"body" => "my message"})

    {:ok, others} =
      Graph.send(c.room, Identity.user_id(c.other.username), "m.room.message", %{
        "body" => "their message"
      })

    assert {:ok, _} = AccountModeration.admin(c.admin.id, c.mxid, :matrix_suspended, true)
    assert api(c.session, :get, "/v3/sync") |> json_response(200) |> Map.has_key?("next_batch")
    assert {:ok, _} = ClientLogin.open(c.user, %{})

    assert api(c.session, :post, "/v3/keys/upload", %{})
           |> json_response(200)
           |> Map.has_key?("one_time_key_counts")

    assert api(c.session, :post, "/v3/search", %{"search_categories" => %{}})
           |> json_response(200) == %{"search_categories" => %{}}

    assert api(c.session, :post, "/v3/createRoom", %{})
           |> json_response(403)
           |> Map.fetch!("errcode") == "M_USER_SUSPENDED"

    assert {:error, :user_suspended} =
             Graph.send(c.room, c.mxid, "m.room.message", %{"body" => "blocked"})

    assert {:error, :user_suspended} =
             ClientProfiles.put(c.user.id, c.mxid, "displayname", "blocked")

    assert {:error, :user_suspended} =
             Graph.send(c.room, c.mxid, "m.room.redaction", %{"redacts" => others["event_id"]})

    assert {:ok, _} =
             Graph.send(c.room, c.mxid, "m.room.redaction", %{"redacts" => own["event_id"]})

    assert api(c.session, :post, "/v3/rooms/" <> URI.encode(c.ref) <> "/leave")
           |> json_response(200)
           |> is_map()
  end

  test "whois is private to the account and administrators and reports only retained device data",
       c do
    path = "/v3/admin/whois/" <> URI.encode(c.mxid)

    assert api(c.session, :get, path) |> json_response(200) == %{
             "user_id" => c.mxid,
             "devices" => %{c.session["device_id"] => %{"sessions" => []}}
           }

    {:ok, other_session} = ClientLogin.open(c.other, %{})

    assert api(other_session, :get, path) |> json_response(403) |> Map.fetch!("errcode") ==
             "M_FORBIDDEN"

    assert api(c.admin_session, :get, path) |> json_response(200) |> Map.fetch!("user_id") ==
             c.mxid
  end

  test "existing River credentials and sockets respect moderation without losing their grants",
       c do
    alias LakehouseIam.Apps.{Grants, Tokens}
    alias LakehouseMatrix.DelegatedGroups

    {:ok, grant} =
      Grants.upsert(
        c.user.id,
        "https://chat.gravitas.cool",
        ~w(chats.list chats.read chats.write groups.create groups.manage),
        :all,
        []
      )

    {:ok, group} =
      DelegatedGroups.create(grant, %{
        "name" => "Moderated group",
        "kind" => "group",
        "txn_id" => "group"
      })

    {:ok, token} = Tokens.issue(grant)

    app_conn = fn ->
      build_conn() |> put_req_header("authorization", "Bearer " <> token.access_token)
    end

    socket = %Phoenix.Socket{
      assigns: %{room_db_id: group.id, principal_id: c.user.id, username: c.user.username}
    }

    assert {:ok, _} = AccountModeration.admin(c.admin.id, c.mxid, :matrix_suspended, true)
    assert get(app_conn.(), "/app/v1/groups") |> json_response(200) |> Map.has_key?("groups")

    assert put(app_conn.(), "/app/v1/groups/#{group.id}/events/m.room.message/blocked", %{
             "content" => %{"body" => "blocked"}
           })
           |> json_response(403)
           |> Map.fetch!("errcode") == "M_USER_SUSPENDED"

    assert {:error, :user_suspended} =
             DelegatedGroups.send(grant, group.id, "m.room.message", "blocked", %{
               "body" => "blocked"
             })

    assert {:stop, :normal, ^socket} =
             LakehouseWeb.RoomChannel.handle_in("typing", %{"typing" => true}, socket)

    assert {:ok, _} = AccountModeration.admin(c.admin.id, c.mxid, :matrix_locked, true)

    assert get(app_conn.(), "/app/v1/groups") |> json_response(401) |> Map.fetch!("errcode") ==
             "M_USER_LOCKED"

    assert {:stop, :normal, ^socket} =
             LakehouseWeb.RoomChannel.handle_info({:room_event, group.id, %{}}, socket)

    assert {:ok, _} = AccountModeration.admin(c.admin.id, c.mxid, :matrix_locked, false)
    assert {:ok, _} = AccountModeration.admin(c.admin.id, c.mxid, :matrix_suspended, false)
    assert get(app_conn.(), "/app/v1/groups") |> json_response(200) |> Map.has_key?("groups")

    assert {:ok, _} =
             DelegatedGroups.send(grant, group.id, "m.room.message", "unlocked", %{
               "body" => "permitted"
             })
  end

  test "classic and sliding long polls detect a lock applied after the request starts", c do
    alias LakehouseMatrix.{ClientSync, SlidingSync}
    device = c.session["device_id"]
    {:ok, initial} = ClientSync.sync(c.user.id, device, %{})
    {:ok, sliding} = SlidingSync.sync(c.user.id, device, %{})

    classic_task =
      Task.async(fn ->
        ClientSync.sync(c.user.id, device, %{"since" => initial["next_batch"], "timeout" => 5000})
      end)

    sliding_task =
      Task.async(fn ->
        SlidingSync.sync(c.user.id, device, %{"pos" => sliding["pos"], "timeout" => 5000})
      end)

    Process.sleep(100)
    assert Task.yield(classic_task, 0) == nil
    assert Task.yield(sliding_task, 0) == nil
    assert {:ok, _} = AccountModeration.admin(c.admin.id, c.mxid, :matrix_locked, true)
    assert {:error, :user_locked} = Task.await(classic_task, 1500)
    assert {:error, :user_locked} = Task.await(sliding_task, 1500)
  end
end
