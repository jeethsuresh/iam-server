defmodule LakehouseWeb.RiverRtcTest do
  use LakehouseWeb.ConnCase
  alias LakehouseIam.{Repo, Apps.Grants, Apps.Tokens}
  alias LakehouseMatrix.{DelegatedGroups, RiverRtc, Identity, State, Sync}
  alias LakehouseMatrix.Schema.RiverRtcMember
  alias LakehouseWeb.MatrixFixtures
  setup do
    old = Application.get_env(:lakehouse_matrix, :rtc_url)
    Application.put_env(:lakehouse_matrix, :rtc_url, "wss://rtc.gravitas.test")
    on_exit(fn -> if old, do: Application.put_env(:lakehouse_matrix,:rtc_url,old), else: Application.delete_env(:lakehouse_matrix,:rtc_url) end)
    a = MatrixFixtures.user_fixture("rtcalice"); b = MatrixFixtures.user_fixture("rtcbob")
    scopes = ~w(chats.list chats.read chats.write groups.create groups.manage groups.join spaces.channels calls.read calls.join)
    {:ok, ga} = Grants.upsert(a.id,"https://chat.gravitas.cool",scopes,:all,[])
    {:ok, gb} = Grants.upsert(b.id,"https://chat.gravitas.cool",scopes,:all,[])
    {:ok, bundle} = Tokens.issue(ga)
    {:ok, %{token: ta}} = Tokens.verify_access(bundle.access_token)
    {:ok, bundle} = Tokens.issue(gb)
    {:ok, %{token: tb}} = Tokens.verify_access(bundle.access_token)
    {:ok, room} = DelegatedGroups.create(ga,%{"name"=>"Call","kind"=>"dm","txn_id"=>"rtc"})
    {:ok, _} = DelegatedGroups.membership(ga,room.id,%{"action"=>"invite","user_id"=>Identity.user_id(b.username)})
    {:ok, _} = DelegatedGroups.membership(gb,room.id,%{"action"=>"accept"})
    %{ga: ga,gb: gb,ta: ta,tb: tb,room: room,id: Base.url_encode64(:crypto.strong_rand_bytes(32),padding: false)}
  end
  test "RTC joins use separate pseudonymous device memberships and sticky Matrix events", %{ga: g,ta: t,room: r,id: id} do
    assert {:ok, join} = RiverRtc.update(g,t,r.id,%{"action"=>"join","member_id"=>id})
    assert join.member_id == id and String.starts_with?(join.livekit_room,"river_")
    refute String.contains?(join.identity,"rtcalice")
    assert State.get(r.id,"m.rtc.slot","m.call#room")["content"]["status"] == "open"
    assert RiverRtc.lease_active?(id)
    {:ok, %{calls: [call]}} = RiverRtc.list(g)
    assert call.group_id == r.id and length(call.participants)==1
    payload = Sync.sync(g.principal_id,nil)
    events = get_in(payload,["rooms","join",r.room_id,"timeline","events"])
    event = Enum.find(events,&(&1["type"]=="m.rtc.member"))
    assert event["sticky"]["duration_ms"]==70_000
    assert event["unsigned"]["sticky_duration_remaining_ms"]>0
    assert {:ok, _} = RiverRtc.update(g,t,r.id,%{"action"=>"renew","member_id"=>id})
    assert {:ok, _} = RiverRtc.update(g,t,r.id,%{"action"=>"leave","member_id"=>id})
    refute RiverRtc.lease_active?(id)
    assert {:error,:membership_expired} = RiverRtc.update(g,t,r.id,%{"action"=>"join","member_id"=>id})
  end
  test "other users cannot change a membership; current consent and token revocation invalidate SFU leases", %{ga: a,gb: b,ta: ta,tb: tb,room: r,id: id} do
    {:ok, _} = RiverRtc.update(a,ta,r.id,%{"action"=>"join","member_id"=>id})
    assert {:error,:forbidden} = RiverRtc.update(b,tb,r.id,%{"action"=>"leave","member_id"=>id})
    assert {:error,:insufficient_scope} = RiverRtc.update(%{a | scopes: []},ta,r.id,%{"action"=>"renew","member_id"=>id})
    assert :ok = Tokens.revoke_grant_tokens(a.id)
    refute RiverRtc.lease_active?(id)
    refute RiverRtc.lease_active?(String.duplicate("a",43))
  end
  test "removed room members and expired device leases cannot remain in calls", %{ga: g,ta: t,room: r,id: id} do
    {:ok, _} = RiverRtc.update(g,t,r.id,%{"action"=>"join","member_id"=>id})
    Repo.get!(RiverRtcMember,id) |> Ecto.Changeset.change(expires_at: DateTime.add(DateTime.utc_now(),-1,:second)) |> Repo.update!()
    refute RiverRtc.lease_active?(id)
    assert {:error,:membership_expired} = RiverRtc.update(g,t,r.id,%{"action"=>"renew","member_id"=>id})
    assert {:ok, _} = DelegatedGroups.membership(g,r.id,%{"action"=>"leave"})
    assert {:error,:forbidden} = RiverRtc.update(g,t,r.id,%{"action"=>"join","member_id"=>String.duplicate("b",43)})
  end
end
