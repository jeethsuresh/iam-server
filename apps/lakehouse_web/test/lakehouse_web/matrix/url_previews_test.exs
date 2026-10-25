defmodule LakehouseWeb.Matrix.UrlPreviewsTest do
  use LakehouseWeb.ConnCase, async: false
  alias LakehouseWeb.MatrixFixtures

  setup do
    user = MatrixFixtures.user_fixture("previewuser")

    session =
      build_conn()
      |> post("/_matrix/client/v3/login", %{
        "type" => "m.login.password",
        "user" => user.username,
        "password" => "password123"
      })
      |> json_response(200)

    old = Application.get_env(:lakehouse_matrix, :url_preview_requester)

    Application.put_env(
      :lakehouse_matrix,
      :url_preview_requester,
      fn "https://example.org/summary" ->
        {:ok,
         %{
           headers: %{"content-type" => "text/html"},
           body: "<title>Matrix summary</title><meta name='description' content='Public page'>"
         }}
      end
    )

    on_exit(fn ->
      if old,
        do: Application.put_env(:lakehouse_matrix, :url_preview_requester, old),
        else: Application.delete_env(:lakehouse_matrix, :url_preview_requester)
    end)

    %{session: session}
  end

  test "standard and legacy preview routes require a token and return only summaries", ctx do
    url = URI.encode_www_form("https://example.org/summary")

    for prefix <- ["/_matrix/client/v1/media/preview_url", "/_matrix/media/v3/preview_url"] do
      assert get(build_conn(), prefix <> "?url=" <> url).status == 401

      result =
        build_conn()
        |> put_req_header("authorization", "Bearer " <> ctx.session["access_token"])
        |> get(prefix <> "?url=" <> url)

      assert json_response(result, 200) == %{
               "og:title" => "Matrix summary",
               "og:description" => "Public page",
               "og:url" => "https://example.org/summary"
             }

      assert get_resp_header(result, "cache-control") == ["no-store"]
    end

    private = URI.encode_www_form("https://127.0.0.1/private")

    result =
      build_conn()
      |> put_req_header("authorization", "Bearer " <> ctx.session["access_token"])
      |> get("/_matrix/client/v1/media/preview_url?url=" <> private)

    assert json_response(result, 403)["errcode"] == "M_FORBIDDEN"

    result =
      build_conn()
      |> put_req_header("authorization", "Bearer " <> ctx.session["access_token"])
      |> get("/_matrix/client/v1/media/preview_url?url[]=invalid")

    assert json_response(result, 400)["errcode"] == "M_INVALID_PARAM"
  end
end
