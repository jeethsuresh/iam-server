defmodule LakehouseIam.Repo.Migrations.ParticipantSubgroups do
  use Ecto.Migration

  def up do
    create table(:participant_sets, primary_key: false) do
      add(:id, :text, primary_key: true)
      add(:members, {:array, :text}, null: false)
      add(:cardinality, :integer, null: false)
      add(:created_at, :utc_datetime_usec, null: false, default: fragment("now()"))
    end

    create(
      constraint(:participant_sets, :nonempty_set,
        check: "cardinality > 0 AND cardinality = cardinality(members)"
      )
    )

    create(index(:participant_sets, [:members], using: :gin))
    create(index(:participant_sets, [:cardinality]))

    create table(:participant_set_edges, primary_key: false) do
      add(:parent_id, references(:participant_sets, type: :text, on_delete: :delete_all),
        primary_key: true
      )

      add(:child_id, references(:participant_sets, type: :text, on_delete: :delete_all),
        primary_key: true
      )
    end

    create(index(:participant_set_edges, [:child_id]))
    create(constraint(:participant_set_edges, :no_self_edge, check: "parent_id <> child_id"))

    create table(:group_subgroups, primary_key: false) do
      add(:group_id, references(:rooms, type: :uuid, on_delete: :delete_all), primary_key: true)
      add(:subgroup_id, references(:participant_sets, type: :text))
      add(:revision, :bigint, null: false)
    end

    create(index(:group_subgroups, [:subgroup_id]))

    create table(:group_subgroup_revisions, primary_key: false) do
      add(:group_id, references(:rooms, type: :uuid, on_delete: :delete_all), primary_key: true)
      add(:revision, :bigint, primary_key: true)
      add(:subgroup_id, references(:participant_sets, type: :text))
      add(:event_id, :text)
      add(:created_at, :utc_datetime_usec, null: false, default: fragment("now()"))
    end

    flush()
    LakehouseMatrix.Subgroups.backfill!()
  end

  def down do
    drop(table(:group_subgroup_revisions))
    drop(table(:group_subgroups))
    drop(table(:participant_set_edges))
    drop(table(:participant_sets))
  end
end
