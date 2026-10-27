# Separate real connections exercise transaction locks that sandboxed unit tests
# cannot race. This script deliberately refuses every non-test database.
alias LakehouseIam.{ParticipantSets, Repo}

unless System.get_env("MIX_ENV") == "test" and
         String.starts_with?(Repo.config()[:database], "lakehouse_test"),
       do: raise("subgroup concurrency checks require the isolated test database")

Ecto.Adapters.SQL.Sandbox.mode(Repo, :auto)
query = fn sql, args -> Ecto.Adapters.SQL.query!(Repo, sql, args) end
room = Ecto.UUID.generate()
dumped = Ecto.UUID.dump!(room)
tag = "subgroup-concurrency:" <> room
members = [tag, tag <> ":peer"]

query.(
  "INSERT INTO rooms(id, name, inserted_at, updated_at) VALUES($1, 'Concurrency check', now(), now())",
  [dumped]
)

try do
  ids =
    1..12
    |> Task.async_stream(
      fn i ->
        ParticipantSets.register!(if rem(i, 2) == 0, do: members, else: Enum.reverse(members))
      end,
      max_concurrency: 4,
      timeout: 30_000
    )
    |> Enum.map(fn {:ok, id} -> id end)

  unless length(Enum.uniq(ids)) == 1, do: raise("concurrent registration created duplicate sets")

  results =
    1..12
    |> Task.async_stream(fn i -> ParticipantSets.bind!(room, [tag, tag <> ":#{i}"]) end,
      max_concurrency: 4,
      timeout: 30_000
    )
    |> Enum.map(fn {:ok, result} -> result end)

  unless length(Enum.uniq(Enum.map(results, & &1.subgroup_revision))) == 12,
    do: raise("concurrent roster changes lost a revision")

  before = ParticipantSets.current(room)

  {:error, :rollback_check} =
    Repo.transaction(fn ->
      ParticipantSets.bind!(room, [tag, tag <> ":rollback"])
      Repo.rollback(:rollback_check)
    end)

  unless before == ParticipantSets.current(room),
    do: raise("failed membership transaction changed its subgroup")

  [[0]] =
    query.(
      """
      SELECT count(*) FROM participant_set_edges e
      JOIN participant_sets p ON p.id=e.parent_id JOIN participant_sets c ON c.id=e.child_id
      WHERE NOT (p.cardinality > c.cardinality AND p.members @> c.members)
        OR EXISTS (SELECT 1 FROM participant_sets m WHERE p.cardinality > m.cardinality
          AND m.cardinality > c.cardinality AND p.members @> m.members AND m.members @> c.members)
      """,
      []
    ).rows

  [[0]] =
    query.(
      """
      WITH RECURSIVE reachable(parent_id, child_id) AS (
        SELECT parent_id, child_id FROM participant_set_edges
        UNION SELECT r.parent_id, e.child_id FROM reachable r JOIN participant_set_edges e ON e.parent_id=r.child_id
      ) SELECT count(*) FROM participant_sets p CROSS JOIN participant_sets c
      WHERE p.cardinality > c.cardinality AND p.members @> c.members
        AND NOT EXISTS (SELECT 1 FROM reachable r WHERE r.parent_id=p.id AND r.child_id=c.id)
      """,
      []
    ).rows

  IO.puts(
    "Subgroup concurrency: canonical registration, twelve revisions, rollback and complete DAG reachability passed"
  )
after
  query.("DELETE FROM rooms WHERE id=$1", [dumped])

  query.(
    "DELETE FROM participant_sets WHERE EXISTS (SELECT 1 FROM unnest(members) member WHERE member LIKE $1)",
    [tag <> "%"]
  )
end
