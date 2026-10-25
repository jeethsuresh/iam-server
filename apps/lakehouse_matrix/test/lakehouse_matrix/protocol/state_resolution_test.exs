defmodule LakehouseMatrix.Protocol.StateResolutionTest do
  use ExUnit.Case, async: true
  alias LakehouseMatrix.Protocol.StateResolution, as: Resolution
  alias LakehouseMatrix.ProtocolFixtures, as: F

  for version <- ["11", "12"] do
    @version version
    test "#{version}: competing topics converge regardless of branch or map ordering" do
      chain = F.public_room(@version)
      {_, first} = F.append(chain, "m.room.topic", %{"topic" => "first"}, key: "", ts: 2_000_000)

      {last, second} =
        F.append(chain, "m.room.topic", %{"topic" => "second"}, key: "", ts: 2_000_001)

      states = [F.state_ids(first), F.state_ids(second)]
      graph = Map.merge(first.graph, second.graph)
      assert {:ok, resolved} = Resolution.resolve(states, graph, @version)
      assert resolved[{"m.room.topic", ""}] == last["event_id"]
      assert Resolution.resolve(Enum.reverse(states), graph, @version) == {:ok, resolved}
      reversed_graph = graph |> Enum.reverse() |> Map.new()
      assert Resolution.resolve(states, reversed_graph, @version) == {:ok, resolved}
    end

    test "#{version}: a ban defeats messages authored from a concurrent pre-ban branch" do
      chain = F.public_room(@version)

      {_, chain} =
        F.append(chain, "m.room.member", %{"membership" => "join"}, key: F.bob(), sender: F.bob())

      levels = chain.state[{"m.room.power_levels", ""}]["content"]

      {_, chain} =
        F.append(
          chain,
          "m.room.power_levels",
          Map.put(levels, "users", Map.put(levels["users"], F.bob(), 50)),
          key: ""
        )

      {original, chain} = F.append(chain, "m.room.topic", %{"topic" => "original"}, key: "")
      {ban, first} = F.append(chain, "m.room.member", %{"membership" => "ban"}, key: F.bob())

      {_, second} =
        F.append(chain, "m.room.topic", %{"topic" => "evade ban"},
          key: "",
          sender: F.bob(),
          ts: 3_000_000
        )

      graph = Map.merge(first.graph, second.graph)

      assert {:ok, resolved} =
               Resolution.resolve([F.state_ids(first), F.state_ids(second)], graph, @version)

      assert resolved[{"m.room.member", F.bob()}] == ban["event_id"]
      assert resolved[{"m.room.topic", ""}] == original["event_id"]
    end

    test "#{version}: missing and cyclic auth graphs fail instead of choosing arbitrary state" do
      chain = F.public_room(@version)
      {event, fork} = F.append(chain, "m.room.topic", %{"topic" => "fork"}, key: "")
      states = [F.state_ids(chain), F.state_ids(fork)]

      assert {:error, {:missing_event, _}} =
               Resolution.resolve(
                 states,
                 Map.delete(fork.graph, chain.create["event_id"]),
                 @version
               )

      graph = put_in(fork.graph, [event["event_id"], "auth_events"], [event["event_id"]])
      assert {:error, :cyclic_auth_graph} = Resolution.resolve(states, graph, @version)
    end
  end
end
