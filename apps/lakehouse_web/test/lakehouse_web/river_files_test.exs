defmodule LakehouseWeb.RiverFilesTest do
  use LakehouseWeb.ConnCase
  import Ecto.Query
  alias LakehouseIam.{Repo, Apps.Grants}
  alias LakehouseMatrix.{DelegatedGroups, RiverFiles}
  alias LakehouseMatrix.Schema.RoomEvent
  alias LakehouseWeb.MatrixFixtures
  setup do
    p = MatrixFixtures.user_fixture("fileowner")
    q = MatrixFixtures.user_fixture("fileoutsider")
    scopes = ~w(chats.list chats.read chats.write groups.create groups.manage groups.join spaces.channels)
    {:ok, g} = Grants.upsert(p.id, "https://chat.gravitas.cool", scopes, :all, [])
    {:ok, other} = Grants.upsert(q.id, "https://chat.gravitas.cool", scopes, :all, [])
    {:ok, r} = DelegatedGroups.create(g, %{"name" => "Files", "kind" => "space", "txn_id" => "files"})
    f = %{"id" => Ecto.UUID.generate(), "name" => "notes.txt", "size" => 20, "mime" => "text/plain", "sha256" => String.duplicate("a",64), "scope" => "room", "targetId" => r.id}
    %{g: g, other: other, r: r, f: f}
  end
  test "manifests and attachment events are immutable and room authorized", %{g: g, other: other, r: r, f: f} do
    content = %{"body" => "Notes", "cool.gravitas.river.attachments" => [f]}
    assert {:ok, event} = DelegatedGroups.send(g, r.id, "m.room.message", "files", content)
    assert {:ok, ^event} = DelegatedGroups.send(g, r.id, "m.room.message", "files", content)
    assert {:ok, %{attachments: [^f]}} = RiverFiles.list(g, r.id, %{})
    assert {:ok, %{attachment: ^f}} = RiverFiles.list(g, r.id, %{"file_id" => f["id"]})
    assert {:error, :forbidden} = RiverFiles.list(other, r.id, %{"file_id" => f["id"]})
    assert Repo.aggregate(from(e in RoomEvent, where: e.type == "cool.gravitas.river.attachment.v1"), :count) == 1
    assert {:error, :transaction_conflict} = DelegatedGroups.send(g, r.id, "m.room.message", "reused-file", content)
  end
  test "oversized, malformed and foreign-room manifests cannot be registered", %{g: g, r: r, f: f} do
    for bad <- [%{f | "size" => 26 * 1024 * 1024}, %{f | "name" => "../secret"}, %{f | "sha256" => "bad"}, %{f | "targetId" => Ecto.UUID.generate()}, %{f | "mime" => "text/html\r\nX:bad"}] do
      assert {:error, :invalid_attachment} = DelegatedGroups.send(g, r.id, "m.room.message", Ecto.UUID.generate(), %{"body" => "File", "cool.gravitas.river.attachments" => [bad]})
    end
    assert {:error, :invalid_attachment} = DelegatedGroups.send(g, r.id, "m.room.message", "duplicate", %{"body" => "File", "cool.gravitas.river.attachments" => [f,f]})
    assert {:ok, %{attachments: []}} = RiverFiles.list(g, r.id, %{})
  end
end
