defmodule LakehouseWeb.RiverConcurrencyTest do
  use ExUnit.Case, async: false
  import Ecto.Query
  alias Ecto.Adapters.SQL.Sandbox
  alias LakehouseIam.{Repo, Apps.Grants}
  alias LakehouseIam.Schema.Principal
  alias LakehouseMatrix.{DelegatedGroups, Identity, Memberships, Social}
  alias LakehouseMatrix.Schema.{Room, RoomEvent}
  alias LakehouseWeb.MatrixFixtures
  @scopes ~w(profile.name chats.list chats.read chats.write groups.create groups.manage groups.join spaces.channels friends.read friends.manage)

  # These races need independent committed PostgreSQL connections. Ordinary shared
  # sandbox tests serialize every query and cannot exercise competing row locks.
  defp with_pair(fun) do
    Sandbox.unboxed_run(Repo, fn ->
      suffix = Base.encode16(:crypto.strong_rand_bytes(4), case: :lower)
      a = MatrixFixtures.user_fixture("racea" <> suffix)
      b = MatrixFixtures.user_fixture("raceb" <> suffix)
      ids = [a.id, b.id]
      try do
        {:ok, ga} = Grants.upsert(a.id, "https://chat.gravitas.cool", @scopes, :all, [])
        {:ok, gb} = Grants.upsert(b.id, "https://chat.gravitas.cool", @scopes, :all, [])
        fun.(a, b, ga, gb)
      after
        rooms = Repo.all(from e in RoomEvent,
          where: e.principal_id in ^ids and e.type == "m.room.create", select: e.room_id)
        Repo.delete_all(from r in Room, where: r.id in ^rooms)
        Repo.delete_all(from p in Principal, where: p.id in ^ids)
      end
    end)
  end

  defp race(operations) do
    parent = self()
    jobs = for operation <- operations do
      Task.async(fn -> Sandbox.unboxed_run(Repo, fn ->
        send(parent, {:ready, self()})
        receive do
          :go -> operation.()
        after
          5000 -> raise "race barrier timed out"
        end
      end) end)
    end
    for _ <- jobs, do: assert_receive({:ready, _}, 5000)
    for job <- jobs, do: send(job.pid, :go)
    Enum.map(jobs, &Task.await(&1, 15000))
  end

  test "concurrent channel creation and parent leave cannot leave a joined child" do
    with_pair(fn _a, b, ga, gb ->
      {:ok, space} = DelegatedGroups.create(ga, %{"name" => "Concurrent space", "kind" => "space", "txn_id" => "space"})
      {:ok, _} = DelegatedGroups.membership(ga, space.id, %{"action" => "invite", "user_id" => Identity.user_id(b.username)})
      {:ok, _} = DelegatedGroups.membership(gb, space.id, %{"action" => "accept"})
      results = race([
        fn -> DelegatedGroups.create_channel(ga, space.id, %{"name" => "racing", "kind" => "text", "txn_id" => "racing"}) end,
        fn -> DelegatedGroups.membership(gb, space.id, %{"action" => "leave"}) end
      ])
      assert [{:ok, channel}, {:ok, _}] = results
      refute Memberships.joined?(space.id, b.id)
      refute Memberships.joined?(channel.id, b.id)
      assert {:error, :forbidden} = DelegatedGroups.timeline(gb, channel.id, %{})
    end)
  end

  test "accepting a request concurrently with a block cannot preserve friendship" do
    with_pair(fn a, b, ga, gb ->
      {:ok, _} = Social.act(ga, %{"action" => "request", "user_id" => Identity.user_id(b.username), "txn_id" => "request"})
      results = race([
        fn -> Social.act(gb, %{"action" => "accept", "user_id" => Identity.user_id(a.username), "txn_id" => "accept"}) end,
        fn -> Social.act(ga, %{"action" => "block", "user_id" => Identity.user_id(b.username), "txn_id" => "block"}) end
      ])
      assert match?([_, {:ok, _}], results)
      refute Social.friends?(a.id, b.id)
      assert Social.blocked?(a.id, b.id)
      assert {:ok, %{friends: [], requests: []}} = Social.list(gb)
    end)
  end
end
