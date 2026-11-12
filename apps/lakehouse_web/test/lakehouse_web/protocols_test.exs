defmodule LakehouseWeb.ProtocolsTest do
  use LakehouseWeb.ConnCase
  alias LakehouseIam.{Accounts, Protocols}
  alias LakehouseIam.Apps.{Grants, Tokens}
  alias LakehouseIam.Auth.Sessions

  @appstore Path.expand("../../../lakehouse_iam/test/fixtures/appstore-1.0.0.json", __DIR__)
            |> File.read!()
            |> Jason.decode!()
  @store "https://apps.example"
  @sender "https://calendar.example"
  @key String.duplicate("s", 48)
  @sender_key String.duplicate("n", 48)
  @other_key String.duplicate("o", 48)

  setup do
    prior = Application.get_env(:lakehouse_iam, :protocol_services)
    owners = Application.get_env(:lakehouse_iam, :protocol_owners)

    Application.put_env(:lakehouse_iam, :protocol_services, %{
      @store => %{"key" => @key, "permissions" => ["protocols.read", "appstore.push"]},
      @sender => %{"key" => @sender_key, "permissions" => ["protocols.read", "appstore.push"]},
      "https://other.example" => %{
        "key" => @other_key,
        "permissions" => ["protocols.read", "appstore.push"]
      }
    })

    Application.put_env(:lakehouse_iam, :protocol_owners, %{"appstore" => @store})

    on_exit(fn ->
      if prior,
        do: Application.put_env(:lakehouse_iam, :protocol_services, prior),
        else: Application.delete_env(:lakehouse_iam, :protocol_services)

      if owners,
        do: Application.put_env(:lakehouse_iam, :protocol_owners, owners),
        else: Application.delete_env(:lakehouse_iam, :protocol_owners)
    end)

    {:ok, p} = Accounts.register_user("protocolapi", "password123", approve: true)
    {:ok, grant} = Grants.upsert(p.id, @store, ["profile.name"], :all, [])
    {:ok, family} = Sessions.issue(p.username, :api)
    {:ok, tokens} = Tokens.issue(grant, session_id(family))
    {:ok, p: p, grant: grant, tokens: tokens}
  end

  test "AppStore receives pushes for an iOS-only login from its originating app" do
    {:ok, user} = Accounts.register_user("iosprotocol", "password123", approve: true)
    {:ok, grant} = Grants.upsert(user.id, @sender, ["profile.name"], :all, [])
    {:ok, family} = Sessions.issue(user.username, :api)
    {:ok, tokens} = Tokens.issue(grant, session_id(family))
    path = "/protocols/v1/registry/appstore"
    body = %{"session_proof" => tokens.session_check_token, "specification" => @appstore}

    assert req(:put, path, @sender_key, body).status == 403
    assert req(:put, path, @key, %{body | "session_proof" => tokens.access_token}).status == 403
    assert req(:put, path, @key, %{body | "specification" => %{"protocol" => "other"}}).status == 400

    assert %{"sub" => subject, "app_origin" => @sender} =
             req(:put, path, @key, body) |> json_response(200)

    assert subject == user.id
    assert req(:put, path, @key, body).status == 200
    user_path = "/protocols/v1/users/#{subject}"
    assert %{"protocols" => [%{"protocol" => "appstore"}]} =
             req(:get, user_path, @sender_key) |> json_response(200)

    assert %{"protocols" => []} = req(:get, user_path, @other_key) |> json_response(200)

    invocation = %{
      "id" => "ios-invite",
      "protocol" => "appstore",
      "version" => "1.0.0",
      "capability" => "push.send",
      "input" => %{
        "app" => "spacetime",
        "device" => String.duplicate("a", 64),
        "payload" => %{"title" => "Dinner"}
      }
    }

    assert req(:post, user_path <> "/invoke", @sender_key, invocation).status == 202
    parent = self()

    Protocols.deliver_once(fn url, {key, envelope} ->
      send(parent, {:delivery, url, key, envelope})
      :ok
    end)

    assert_received {:delivery, "https://apps.example/api/protocols/invoke", @key,
                     %{"subject" => ^subject, "sender" => @sender}}

    # A Store login for the same account still produces one relay envelope.
    {:ok, store_grant} = Grants.upsert(subject, @store, ["profile.name"], :all, [])
    assert {:ok, :ok} = Protocols.register(store_grant, registry())
    assert req(:post, user_path <> "/invoke", @sender_key, %{invocation | "id" => "mixed"}).status ==
             202

    assert LakehouseIam.Repo.aggregate(LakehouseIam.Protocols.Delivery, :count) == 1
    assert :ok = Grants.revoke(grant.id)
    assert :ok = Grants.revoke(store_grant.id)
    assert %{"protocols" => []} = req(:get, user_path, @sender_key) |> json_response(200)
  end

  defp req(method, path, token, body \\ %{}) do
    build_conn()
    |> put_req_header("authorization", "Bearer " <> token)
    |> put_req_header("content-type", "application/json")
    |> dispatch(LakehouseWeb.Endpoint, method, path, Jason.encode!(body))
  end

  defp session_id(family) do
    {:ok, claims} = LakehouseIam.Auth.Token.verify(family.token)
    claims["sid"]
  end

  defp registry, do: %{"schema_version" => 1, "protocols" => [@appstore]}

  test "login token registers PCR; service discovery never returns app/provider details", %{
    p: p,
    tokens: tokens
  } do
    assert req(:put, "/app/v1/protocols/registry", tokens.access_token, registry()).status == 204
    response = req(:get, "/protocols/v1/users/#{p.id}", @key) |> json_response(200)
    assert [%{"protocol" => "appstore", "version" => "1.0.0"}] = response["protocols"]
    refute Jason.encode!(response) =~ @store
    assert req(:get, "/protocols/v1/users/#{p.id}", tokens.access_token).status == 403
    assert req(:get, "/protocols/v1/specifications", "unknown").status == 401

    assert req(:put, "/app/v1/protocols/registry", tokens.session_check_token, registry()).status ==
             401
  end

  test "backfill needs both a backend credential and a matching live session proof", %{
    p: p,
    tokens: tokens
  } do
    body = %{"session_proof" => tokens.session_check_token, "registry" => registry()}
    assert req(:put, "/protocols/v1/registry", @key, body).status == 204
    assert req(:put, "/protocols/v1/registry", tokens.access_token, body).status == 403
    {:ok, other_grant} = Grants.upsert(p.id, @sender, ["profile.name"], :all, [])
    {:ok, family} = Sessions.issue(p.username, :api)
    {:ok, other_tokens} = Tokens.issue(other_grant, session_id(family))

    assert req(:put, "/protocols/v1/registry", @key, %{
             body
             | "session_proof" => other_tokens.session_check_token
           }).status == 403

    assert req(:put, "/protocols/v1/registry", @key, %{body | "session_proof" => "invalid"}).status ==
             403

    assert length(Protocols.subscribed(p.id, %{permissions: ["appstore.push"]})) == 1
  end

  test "an authorized invocation returns only a fixed asynchronous receipt", %{p: p, grant: grant} do
    assert {:ok, _} = Protocols.register(grant, registry())

    body = %{
      "id" => "test",
      "protocol" => "appstore",
      "version" => "1.0.0",
      "capability" => "push.send",
      "input" => %{
        "app" => "spacetime",
        "device" => String.duplicate("a", 64),
        "payload" => %{"title" => "Dinner"}
      }
    }

    assert %{"id" => "test", "status" => "accepted"} =
             req(:post, "/protocols/v1/users/#{p.id}/invoke", @key, body) |> json_response(202)

    assert %{"id" => "test", "status" => "accepted"} =
             req(:post, "/protocols/v1/users/#{Ecto.UUID.generate()}/invoke", @key, %{
               body
               | "id" => "test2"
             })
             |> json_response(202)
             |> Map.put("id", "test")
  end
end
