defmodule LakehouseIam.Repo.Migrations.RequireServiceBranding do
  use Ecto.Migration

  def up do
    alter table(:services) do
      add :logo_url, :text
    end

    execute """
    UPDATE services AS s
    SET name = brand.name,
        description = brand.description,
        logo_url = '/images/services/' || brand.logo
    FROM (VALUES
      ('https://news.gravitas.cool', 'News', 'Read your hosted RSS feeds, catch up on unread articles and return to saved items.', 'news.svg'),
      ('https://work.gravitas.cool', 'Office', 'Keep documents, canvases, slides and spreadsheets together in one workspace.', 'office.png'),
      ('https://games.gravitas.cool', 'Railyard', 'Host browser game lobbies and phone parties, or play a quick solo arcade game.', 'railyard.svg'),
      ('https://chat.gravitas.cool', 'River', 'Give each group a space and each topic its own channel. Chat with friends, share posts and follow discussions.', 'river.svg'),
      ('https://spacetime.gravitas.cool', 'Spacetime', 'Keep events, tasks and birthdays in one calendar. Connect a Spacetime server when you want sync and invitations.', 'spacetime.svg')
    ) AS brand(origin, name, description, logo)
    WHERE s.origin = brand.origin
    """

    # Existing services can be completed in place by an administrator.
    execute """
    ALTER TABLE services ADD CONSTRAINT services_branding_present
    CHECK (name ~ '[^[:space:]]' AND
           description IS NOT NULL AND description ~ '[^[:space:]]' AND
           logo_url IS NOT NULL AND logo_url ~ '[^[:space:]]') NOT VALID
    """
  end

  def down do
    execute "ALTER TABLE services DROP CONSTRAINT services_branding_present"

    alter table(:services) do
      remove :logo_url
    end
  end
end
