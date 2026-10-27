defmodule LakehouseIam.ParticipantSetsTest do
  use LakehouseIam.DataCase
  alias LakehouseIam.ParticipantSets, as: Sets

  defp sql(statement, args \\ []), do: Ecto.Adapters.SQL.query!(Repo, statement, args)

  test "only registered sets exist, singleton is minimum, and insertion maintains all cover edges" do
    assert_raise ArgumentError, fn -> Sets.register!([]) end
    [[baseline]] = sql("SELECT count(*) FROM participant_sets").rows
    abc = Sets.register!(~w(a b c))
    abd = Sets.register!(~w(a b d))
    ab = Sets.register!(~w(b a a))
    assert ab == Sets.register!(~w(a b))
    assert Enum.sort(Sets.relations(ab).parents) == Enum.sort([abc, abd])
    assert length(Sets.relations(abc).descendants) == 4
    assert Sets.relations("unknown") == nil
    assert [[total]] = sql("SELECT count(*) FROM participant_sets").rows
    assert total == baseline + 7

    assert [[2]] =
             sql("SELECT count(*) FROM participant_set_edges WHERE child_id = $1", [ab]).rows

    assert [[0]] =
             sql(
               "SELECT count(*) FROM participant_set_edges WHERE parent_id = $1 AND child_id = $2",
               [abc, abd]
             ).rows

    assert [[0]] =
             sql("""
             SELECT count(*) FROM participant_set_edges e
             JOIN participant_sets p ON p.id=e.parent_id JOIN participant_sets c ON c.id=e.child_id
             WHERE NOT (p.cardinality > c.cardinality AND p.members @> c.members)
               OR EXISTS (SELECT 1 FROM participant_sets m WHERE p.cardinality > m.cardinality
                 AND m.cardinality > c.cardinality AND p.members @> m.members AND m.members @> c.members)
             """).rows

    assert [[0]] =
             sql("""
             WITH RECURSIVE reachable(parent_id, child_id) AS (
               SELECT parent_id, child_id FROM participant_set_edges
               UNION SELECT r.parent_id, e.child_id FROM reachable r JOIN participant_set_edges e ON e.parent_id=r.child_id
             ) SELECT count(*) FROM participant_sets p CROSS JOIN participant_sets c
             WHERE p.cardinality > c.cardinality AND p.members @> c.members
               AND NOT EXISTS (SELECT 1 FROM reachable r WHERE r.parent_id=p.id AND r.child_id=c.id)
             """).rows
  end

  test "group identity persists across audience changes and empty membership" do
    room = Ecto.UUID.generate()

    Repo.insert_all("rooms", [
      %{
        id: Ecto.UUID.dump!(room),
        name: "Context",
        inserted_at: DateTime.utc_now(),
        updated_at: DateTime.utc_now()
      }
    ])

    first = Sets.bind!(room, ~w(a b), "$one")
    assert first == Sets.bind!(room, ~w(b a), "$profile")
    second = Sets.bind!(room, ~w(a b c), "$two")
    refute first.subgroup_id == second.subgroup_id
    assert second.subgroup_revision == 2
    empty = Sets.bind!(room, [], "$three")
    assert empty.subgroup_id == nil
    assert empty.subgroup_revision == 3
    assert [[3]] = sql("SELECT count(*) FROM group_subgroup_revisions").rows
    assert Sets.bind!(room, ~w(a b)).subgroup_id == first.subgroup_id
  end
end
