defmodule LakehouseWeb.AccountProfileTest do
  use LakehouseWeb.ConnCase
  alias LakehouseIam.{Profiles, Repo, Schema.Principal}
  alias LakehouseIam.Apps.{Grants, Tokens}
  alias LakehouseWeb.MatrixFixtures

  setup do
    user = MatrixFixtures.user_fixture("profileuser")
    {:ok, user: user}
  end

  defp browser(user) do
    build_conn()
    |> Plug.Test.init_test_session(%{user_jwt: MatrixFixtures.browser_token(user.username)})
  end

  defp me(user, scopes, origin \\ "https://profiles.example") do
    {:ok, grant} = Grants.upsert(user.id, origin, scopes, :selected)
    {:ok, bundle} = Tokens.issue(grant)

    build_conn()
    |> put_req_header("authorization", "Bearer " <> bundle.access_token)
    |> get("/app/v1/me")
  end

  test "full names persist without exposing usernames; each profile permission is independent", %{
    user: user
  } do
    assert {:ok, _} = Profiles.update(user.id, %{"full_name" => "  Ada Lovelace  "})
    response = me(user, ["profile.name"])
    assert get_resp_header(response, "cache-control") == ["no-store"]
    assert %{"name" => "Ada Lovelace", "sub" => subject} = json_response(response, 200)
    assert subject == user.id
    refute Map.has_key?(json_response(response, 200), "username")
    refute Map.has_key?(json_response(response, 200), "user_id")
    refute Map.has_key?(json_response(response, 200), "picture")
    body = me(user, ["profile.username"], "https://username.example") |> json_response(200)
    assert body["username"] == user.username
    assert body["user_id"] == LakehouseIam.Identifier.format(user.username)
    refute Map.has_key?(body, "name")
    assert me(user, [], "https://empty.example").status == 403
    assert {:ok, %{full_name: nil}} = Profiles.update(user.id, %{"full_name" => ""})
  end

  test "upload, serve and remove a picture through settings; links reveal no username", %{
    user: user
  } do
    path = Path.join(System.tmp_dir!(), "profile-#{Ecto.UUID.generate()}.png")

    bytes =
      Base.decode64!(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aD1sAAAAASUVORK5CYII="
      )

    File.write!(path, bytes)
    on_exit(fn -> File.rm(path) end)
    upload = %Plug.Upload{path: path, filename: "private.png", content_type: "text/plain"}

    result =
      post(browser(user), "/web/settings/profile", %{
        "full_name" => "Ada Lovelace",
        "picture" => upload
      })

    assert redirected_to(result) == "/settings"
    profile = Repo.get!(Principal, user.id)
    assert profile.full_name == "Ada Lovelace"
    body = me(user, ["profile.picture"]) |> json_response(200)
    refute Map.has_key?(body, "username")
    refute Map.has_key?(body, "name")
    uri = URI.parse(body["picture"])
    refute String.contains?(uri.path, user.username)
    image = get(build_conn(), uri.path)
    assert response(image, 200) == bytes
    assert get_resp_header(image, "content-type") == ["image/png; charset=utf-8"]
    assert get_resp_header(image, "cache-control") == ["no-store"]
    assert html_response(get(browser(user), "/settings"), 200) =~ "Ada Lovelace"
    assert {:ok, _} = Profiles.update(user.id, %{"remove_picture" => "true"})
    assert get(build_conn(), uri.path).status == 404
  end

  test "oversized names, active images and oversized uploads leave the profile intact", %{
    user: user
  } do
    assert {:ok, _} = Profiles.update(user.id, %{"full_name" => "Original"})
    assert {:error, _} = Profiles.update(user.id, %{"full_name" => String.duplicate("a", 121)})
    path = Path.join(System.tmp_dir!(), "invalid-profile-#{Ecto.UUID.generate()}")
    on_exit(fn -> File.rm(path) end)

    for bytes <- ["<svg onload='alert(1)'/>", String.duplicate("a", 256 * 1024 + 1)] do
      File.write!(path, bytes)
      upload = %Plug.Upload{path: path, filename: "picture.png", content_type: "image/png"}

      assert {:error, :invalid_picture} =
               Profiles.update(user.id, %{"full_name" => "Changed", "picture" => upload})
    end

    assert Repo.get!(Principal, user.id).full_name == "Original"
    assert get(build_conn(), "/profile/pictures/not-a-key").status == 404

    refute post(build_conn(), "/web/settings/profile", %{"full_name" => "Intruder"}).status in [
             200,
             201
           ]
  end

  test "old tokens never inherit newly approved username or picture access", %{user: user} do
    {:ok, grant} = Grants.upsert(user.id, "https://legacy.example", ["profile.name"], :selected)
    {:ok, old} = Tokens.issue(grant)

    {:ok, _} =
      Grants.upsert(user.id, grant.app_origin, ["profile.username", "profile.picture"], :selected)

    body =
      build_conn()
      |> put_req_header("authorization", "Bearer " <> old.access_token)
      |> get("/app/v1/me")
      |> json_response(200)

    refute Map.has_key?(body, "username")
    refute Map.has_key?(body, "picture")

    assert Tokens.effective_scopes(%LakehouseIam.Schema.AppToken{scopes: nil}, %{
             grant
             | scopes: ["profile.name", "profile.username", "profile.picture"]
           }) == ["profile.name"]
  end
end
