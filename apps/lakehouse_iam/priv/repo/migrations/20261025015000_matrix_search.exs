defmodule LakehouseIam.Repo.Migrations.MatrixSearch do
  use Ecto.Migration

  def up do
    execute("""
    CREATE FUNCTION matrix_search_text(event_type text, content jsonb) RETURNS text
    LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
      SELECT CASE event_type
        WHEN 'm.room.message' THEN CASE WHEN jsonb_typeof(content->'body') = 'string' THEN content->>'body' ELSE '' END
        WHEN 'm.room.name' THEN CASE WHEN jsonb_typeof(content->'name') = 'string' THEN content->>'name' ELSE '' END
        WHEN 'm.room.topic' THEN
          (CASE WHEN jsonb_typeof(content->'topic') = 'string' THEN content->>'topic' ELSE '' END) || ' ' ||
          COALESCE((SELECT string_agg(part->>'body', ' ') FROM jsonb_array_elements(
            CASE WHEN jsonb_typeof(content->'m.topic') = 'array' THEN content->'m.topic' ELSE '[]'::jsonb END
          ) AS part WHERE part->>'mimetype' = 'text/plain' AND jsonb_typeof(part->'body') = 'string'), '')
        ELSE '' END
    $$
    """)

    execute(
      "CREATE INDEX matrix_search_events ON room_events USING gin (to_tsvector('english', matrix_search_text(type, content)))"
    )
  end

  def down do
    execute("DROP INDEX matrix_search_events")
    execute("DROP FUNCTION matrix_search_text(text, jsonb)")
  end
end
