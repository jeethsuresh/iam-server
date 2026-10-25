defmodule LakehouseMatrix.Protocol.ReferenceTest do
  use ExUnit.Case, async: true
  alias LakehouseMatrix.Protocol.{Event, StateResolution}
  alias LakehouseMatrix.ProtocolFixtures, as: F
  @fixtures Path.expand("../../fixtures/protocol/synapse-1.163.2.json", __DIR__)
  @external_resource @fixtures

  for fixture <- Jason.decode!(File.read!(@fixtures))["cases"] do
    @fixture fixture
    test "Synapse v1.163.2 agrees on #{@fixture["name"]}" do
      version = @fixture["version"]

      graph =
        Map.new(@fixture["events"], fn %{"id" => id, "pdu" => pdu} ->
          {:ok, server} = Event.user_domain(pdu["sender"])
          signed = Event.sign(pdu, version, F.seed(), "ed25519:test", server)
          assert signed["hashes"] == pdu["hashes"]
          assert signed["signatures"] == pdu["signatures"]
          assert Event.id(pdu, version) == id
          assert {:ok, _} = Event.verify(pdu, version, &F.lookup/3)
          {id, Map.put(pdu, "event_id", id)}
        end)

      state = fn entries -> Map.new(entries, fn [type, key, id] -> {{type, key}, id} end) end
      expected = state.(@fixture["expected_state"])
      states = Enum.map(@fixture["states"], state)
      assert {:ok, ^expected} = StateResolution.resolve(states, graph, version)
      assert {:ok, ^expected} = StateResolution.resolve(Enum.reverse(states), graph, version)
    end
  end
end
