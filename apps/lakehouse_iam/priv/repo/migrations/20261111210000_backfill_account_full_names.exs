defmodule LakehouseIam.Repo.Migrations.BackfillAccountFullNames do
  use Ecto.Migration

  def up do
    execute("""
    UPDATE principals
       SET full_name = username::text
     WHERE type = 'user'
       AND username IS NOT NULL
       AND (full_name IS NULL OR full_name ~ '^[[:space:]]*$')
    """)
  end

  # A matching name could have been entered by the user after the backfill.
  def down, do: :ok
end
