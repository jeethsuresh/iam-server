defmodule LakehouseWeb.DiscoveryTest do
  use LakehouseWeb.ConnCase
  alias LakehouseIam.Discovery

  setup do
    old_domain = Application.get_env(:lakehouse_iam, :identity_domain)
    old_url = Application.get_env(:lakehouse_iam, :public_url)
    old_matrix_url = Application.get_env(:lakehouse_matrix, :public_url)
    Application.delete_env(:lakehouse_matrix, :public_url)
    Application.put_env(:lakehouse_iam, :identity_domain, "example.com")
    Application.put_env(:lakehouse_iam, :public_url, "https://iam.example.com")

    on_exit(fn ->
      Application.put_env(:lakehouse_iam, :identity_domain, old_domain)
      Application.put_env(:lakehouse_iam, :public_url, old_url)

      if old_matrix_url,
        do: Application.put_env(:lakehouse_matrix, :public_url, old_matrix_url),
        else: Application.delete_env(:lakehouse_matrix, :public_url)
    end)
  end

  test "delegated Matrix transport retains IAM discovery and the signed server identity" do
    old_domain = Application.get_env(:lakehouse_matrix, :homeserver_domain)
    old_key = Application.get_env(:lakehouse_matrix, :signing_key)
    Application.put_env(:lakehouse_matrix, :homeserver_domain, "example.com")

    Application.put_env(
      :lakehouse_matrix,
      :signing_key,
      Base.encode64(<<0::256>>, padding: false)
    )

    on_exit(fn ->
      Application.put_env(:lakehouse_matrix, :homeserver_domain, old_domain)

      if old_key,
        do: Application.put_env(:lakehouse_matrix, :signing_key, old_key),
        else: Application.delete_env(:lakehouse_matrix, :signing_key)
    end)

    for {url, address} <- [
          {"https://chat.example.com", "chat.example.com:443"},
          {"https://chat.example.com:9443/", "chat.example.com:9443"}
        ] do
      Application.put_env(:lakehouse_matrix, :public_url, url)
      client = build_conn() |> get("/.well-known/matrix/client") |> json_response(200)
      assert client["m.homeserver"]["base_url"] == String.trim_trailing(url, "/")
      server = build_conn() |> get("/.well-known/matrix/server") |> json_response(200)
      assert server["m.server"] == address
      config = build_conn() |> get("/.well-known/iam-configuration") |> json_response(200)
      assert config["issuer"] == "https://iam.example.com"
      keys = build_conn() |> get("/_matrix/key/v2/server") |> json_response(200)
      assert keys["server_name"] == "example.com"
      assert Map.has_key?(keys["signatures"], "example.com")
    end
  end

  test "public discovery documents point to the canonical subdomain" do
    conn =
      get(build_conn(), "/.well-known/webfinger",
        resource: "acct:alice@example.com",
        rel: Discovery.issuer_rel()
      )

    assert conn.status == 200
    assert get_resp_header(conn, "content-type") == ["application/jrd+json; charset=utf-8"]
    assert get_resp_header(conn, "access-control-allow-origin") == ["*"]

    assert Jason.decode!(conn.resp_body)["links"] |> hd() |> Map.get("href") ==
             "https://iam.example.com"

    config = build_conn() |> get("/.well-known/iam-configuration") |> json_response(200)
    assert config["authorization_endpoint"] == "https://iam.example.com/oauth/authorize"
    matrix = build_conn() |> get("/.well-known/matrix/client") |> json_response(200)
    assert matrix["m.homeserver"]["base_url"] == "https://iam.example.com"
    assert get(build_conn(), "/.well-known/webfinger").status == 400

    assert get(build_conn(), "/.well-known/webfinger", resource: "acct:alice@evil.example").status ==
             404
  end

  test "browser apps can preflight PKCE and bearer endpoints without cookie credentials" do
    for path <- ["/backend/register", "/oauth/token", "/app/v1/me", "/.well-known/webfinger"] do
      conn = options(build_conn(), path)
      assert conn.status == 204
      assert get_resp_header(conn, "access-control-allow-origin") == ["*"]
      assert get_resp_header(conn, "access-control-allow-credentials") == []
    end
  end
end
