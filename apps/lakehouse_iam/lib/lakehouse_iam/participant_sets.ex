defmodule LakehouseIam.ParticipantSets do
  @moduledoc "Registered nonempty participant sets and their strict-containment DAG. Never an ACL."
  alias LakehouseIam.Repo

  def principal(id), do: "principal:" <> id

  def register!(members) do
    transaction!(fn ->
      lock!()
      members = Enum.sort(Enum.uniq(members))
      if members == [], do: raise(ArgumentError, "a participant set cannot be empty")
      for member <- members, do: insert!([member])
      insert!(members)
    end)
  end

  def current(group) do
    case query("SELECT subgroup_id, revision FROM group_subgroups WHERE group_id = $1", [
           uuid(group)
         ]).rows do
      [[id, revision]] -> %{subgroup_id: id, subgroup_revision: revision}
      [] -> %{subgroup_id: nil, subgroup_revision: 0}
    end
  end

  @doc "Internal registry traversal. Callers must authorize public projections separately."
  def relations(id) do
    case query("SELECT members FROM participant_sets WHERE id = $1", [id]).rows do
      [] ->
        nil

      [[members]] ->
        traverse = fn from, to ->
          # Column names are fixed here, never supplied by API input.
          query(
            """
            WITH RECURSIVE related(id) AS (
              SELECT #{to} FROM participant_set_edges WHERE #{from} = $1
              UNION SELECT e.#{to} FROM participant_set_edges e JOIN related r ON e.#{from} = r.id
            ) SELECT id FROM related ORDER BY id
            """,
            [id]
          ).rows
          |> List.flatten()
        end

        ancestors = traverse.("child_id", "parent_id")
        descendants = traverse.("parent_id", "child_id")

        groups = fn sets ->
          query(
            "SELECT group_id FROM group_subgroups WHERE subgroup_id = ANY($1::text[]) ORDER BY group_id",
            [sets]
          ).rows
          |> Enum.map(fn [group] -> Ecto.UUID.load!(group) end)
        end

        %{
          id: id,
          members: members,
          parents:
            query(
              "SELECT parent_id FROM participant_set_edges WHERE child_id = $1 ORDER BY parent_id",
              [id]
            ).rows
            |> List.flatten(),
          children:
            query(
              "SELECT child_id FROM participant_set_edges WHERE parent_id = $1 ORDER BY child_id",
              [id]
            ).rows
            |> List.flatten(),
          ancestors: ancestors,
          descendants: descendants,
          containing_groups: groups.(ancestors),
          contained_groups: groups.(descendants),
          same_participant_groups: groups.([id])
        }
    end
  end

  def bind!(group, members, event_id \\ nil) do
    transaction!(fn ->
      lock!()
      id = if members != [], do: register!(members)
      previous = current(group)

      if previous.subgroup_revision == 0 or previous.subgroup_id != id do
        revision = previous.subgroup_revision + 1

        query(
          """
          INSERT INTO group_subgroups (group_id, subgroup_id, revision) VALUES ($1, $2, $3)
          ON CONFLICT (group_id) DO UPDATE SET subgroup_id = EXCLUDED.subgroup_id, revision = EXCLUDED.revision
          """,
          [uuid(group), id, revision]
        )

        query(
          """
          INSERT INTO group_subgroup_revisions (group_id, revision, subgroup_id, event_id)
          VALUES ($1, $2, $3, $4)
          """,
          [uuid(group), revision, id, event_id]
        )
      end

      current(group)
    end)
  end

  # Only the caller's already-authorized groups are compared. Hidden sets cannot
  # affect edges, counts, or pagination in this projection.
  def projection(group, groups) do
    ids = Enum.map(groups, &uuid(&1.id))

    rows =
      query(
        """
        SELECT g.group_id, g.subgroup_id, g.revision, s.members
        FROM group_subgroups g JOIN participant_sets s ON s.id = g.subgroup_id
        WHERE g.group_id = ANY($1::uuid[])
        """,
        [ids]
      ).rows

    records =
      Map.new(rows, fn [id, set, revision, members] ->
        {Ecto.UUID.load!(id),
         %{subgroup_id: set, revision: revision, members: MapSet.new(members)}}
      end)

    target = records[group]

    if target do
      visible = for g <- groups, r = records[g.id], not is_nil(r), do: {g, r}

      containing =
        Enum.filter(visible, fn {_, r} -> proper_subset?(target.members, r.members) end)

      contained = Enum.filter(visible, fn {_, r} -> proper_subset?(r.members, target.members) end)
      equal = Enum.filter(visible, fn {g, r} -> g.id != group and r.members == target.members end)

      nearest = fn entries, direction ->
        Enum.reject(entries, fn {_, r} ->
          Enum.any?(entries, fn {_, middle} ->
            if direction == :up,
              do: proper_subset?(middle.members, r.members),
              else: proper_subset?(r.members, middle.members)
          end)
        end)
      end

      describe = fn entries ->
        Enum.map(entries, fn {g, r} ->
          Map.take(g, [:id, :name, :kind, :room_id]) |> Map.put(:subgroup_id, r.subgroup_id)
        end)
      end

      %{
        subgroup_id: target.subgroup_id,
        revision: target.revision,
        participant_count: MapSet.size(target.members),
        parents: describe.(nearest.(containing, :up)),
        children: describe.(nearest.(contained, :down)),
        containing_groups: describe.(containing),
        contained_groups: describe.(contained),
        same_participant_groups: describe.(equal),
        singletons:
          Enum.map(Enum.sort(target.members), fn member ->
            %{subgroup_id: fingerprint([member]), participant_id: member}
          end)
      }
    else
      %{
        subgroup_id: nil,
        revision: current(group).subgroup_revision,
        participant_count: 0,
        parents: [],
        children: [],
        containing_groups: [],
        contained_groups: [],
        same_participant_groups: [],
        singletons: []
      }
    end
  end

  defp proper_subset?(a, b), do: MapSet.size(a) < MapSet.size(b) and MapSet.subset?(a, b)

  defp insert!(members) do
    id = fingerprint(members)

    result =
      query(
        """
        INSERT INTO participant_sets (id, members, cardinality) VALUES ($1, $2, $3)
        ON CONFLICT (id) DO NOTHING RETURNING id
        """,
        [id, members, length(members)]
      )

    if result.num_rows == 1 do
      # A new intermediate node replaces any previously immediate edge spanning it.
      query(
        """
        DELETE FROM participant_set_edges e USING participant_sets p, participant_sets c
        WHERE p.id = e.parent_id AND c.id = e.child_id
          AND p.cardinality > $2 AND c.cardinality < $2
          AND p.members @> $1::text[] AND $1::text[] @> c.members
        """,
        [members, length(members)]
      )

      query(
        """
        INSERT INTO participant_set_edges (parent_id, child_id)
        SELECT p.id, $1 FROM participant_sets p
        WHERE p.cardinality > $3 AND p.members @> $2::text[] AND NOT EXISTS (
          SELECT 1 FROM participant_sets m WHERE m.cardinality > $3
            AND m.cardinality < p.cardinality AND p.members @> m.members AND m.members @> $2::text[])
        ON CONFLICT DO NOTHING
        """,
        [id, members, length(members)]
      )

      query(
        """
        INSERT INTO participant_set_edges (parent_id, child_id)
        SELECT $1, c.id FROM participant_sets c
        WHERE c.cardinality < $3 AND $2::text[] @> c.members AND NOT EXISTS (
          SELECT 1 FROM participant_sets m WHERE m.cardinality < $3
            AND m.cardinality > c.cardinality AND $2::text[] @> m.members AND m.members @> c.members)
        ON CONFLICT DO NOTHING
        """,
        [id, members, length(members)]
      )
    else
      [[existing]] = query("SELECT members FROM participant_sets WHERE id = $1", [id]).rows
      unless existing == members, do: raise("participant set fingerprint collision")
    end

    id
  end

  defp fingerprint(members),
    do: :crypto.hash(:sha256, Jason.encode!(members)) |> Base.encode16(case: :lower)

  defp lock!, do: query("SELECT pg_advisory_xact_lock(718492671)", [])
  defp uuid(id), do: Ecto.UUID.dump!(id)
  defp query(sql, args), do: Ecto.Adapters.SQL.query!(Repo, sql, args)

  defp transaction!(callback) do
    if Repo.in_transaction?() do
      callback.()
    else
      case Repo.transaction(callback) do
        {:ok, value} -> value
        {:error, reason} -> raise "participant set transaction failed: #{inspect(reason)}"
      end
    end
  end
end
