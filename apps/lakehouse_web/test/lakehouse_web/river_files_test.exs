defmodule LakehouseWeb.RiverFilesTest do
  use LakehouseWeb.ConnCase
  alias LakehouseIam.Apps.Grants
  alias LakehouseMatrix.DelegatedGroups
  alias LakehouseWeb.MatrixFixtures

  test "delegated messages reject retired peer manifests but still accept standard Matrix media" do
    owner = MatrixFixtures.user_fixture("fileowner")

    scopes =
      ~w(chats.list chats.read chats.write groups.create groups.manage groups.join spaces.channels)

    {:ok, grant} = Grants.upsert(owner.id, "https://chat.gravitas.cool", scopes, :all, [])

    {:ok, room} =
      DelegatedGroups.create(grant, %{"name" => "Files", "kind" => "space", "txn_id" => "files"})

    file = %{
      "id" => Ecto.UUID.generate(),
      "name" => "notes.txt",
      "size" => 20,
      "mime" => "text/plain",
      "sha256" => String.duplicate("a", 64),
      "scope" => "room",
      "targetId" => room.id
    }

    for files <- [[file], %{}, "old manifest"] do
      assert {:error, :invalid_attachment} =
               DelegatedGroups.send(grant, room.id, "m.room.message", Ecto.UUID.generate(), %{
                 "body" => "Notes",
                 "cool.gravitas.river.attachments" => files
               })
    end

    assert {:ok, _} =
             DelegatedGroups.send(grant, room.id, "m.room.message", "standard", %{
               "body" => "notes.txt",
               "msgtype" => "m.file",
               "url" => "mxc://localhost/file-id"
             })

    assert {:ok, _} =
             DelegatedGroups.send(grant, room.id, "m.room.message", "text", %{"body" => "Hello"})

    assert get(build_conn(), "/app/v1/groups/#{room.id}/files").status == 404
  end
end
