defmodule LakehouseWeb.Bdd.IamSteps do
  use Cucumber.StepDefinition
  import ExUnit.Assertions
  import Phoenix.ConnTest

  alias LakehouseIam.Accounts
  alias LakehouseWeb.MatrixFixtures
  alias LakehouseWeb.Test.Api.IamClient

  @endpoint LakehouseWeb.Endpoint

  step "an approved user {string} with password {string}",
       %{args: [username, password]} = context do
    _ = MatrixFixtures.user_fixture(username)

    if password != "password123" do
      :ok = Accounts.change_own_password(username, "password123", password, password)
    end

    users = Map.get(context, :users, %{})
    {:ok, Map.put(context, :users, Map.put(users, username, password))}
  end

  step "a pending user {string} with password {string}",
       %{args: [username, password]} = context do
    MatrixFixtures.ensure_rbac!()
    {:ok, principal} = Accounts.register_user(username, password, approve: false)
    refute principal.active

    pending = Map.get(context, :pending, %{})
    {:ok, Map.put(context, :pending, Map.put(pending, username, password))}
  end

  step "the bootstrap admin is available", context do
    admin = Application.fetch_env!(:lakehouse_iam, :admin_username)
    password = Application.fetch_env!(:lakehouse_iam, :admin_password)
    _ = LakehouseIam.Bootstrap.run()

    {:ok, Map.put(context, :admin, %{username: admin, password: password})}
  end

  step "I register via API as {string} with password {string}",
       %{args: [username, password]} = context do
    conn = IamClient.register(username, password)

    {:ok,
     Map.merge(context, %{last_conn: conn, last_username: username, last_password: password})}
  end

  step "I register via API as {string} with password {string} and key {string}",
       %{args: [username, password, key]} = context do
    conn = IamClient.register(username, password, key)
    {:ok, Map.put(context, :last_conn, conn)}
  end

  step "account {string} should not exist", %{args: [username]} do
    refute Accounts.user_exists?(username)
    :ok
  end

  step "I submit overlapping API registrations for {string} with key {string}",
       %{args: [username, key]} = context do
    responses =
      1..2
      |> Task.async_stream(fn _ -> IamClient.register(username, "password123", key) end,
        max_concurrency: 2,
        timeout: 15_000
      )
      |> Enum.map(fn {:ok, conn} -> conn end)

    {:ok, Map.put(context, :registration_responses, responses)}
  end

  step "one registration succeeds and the other reports a duplicate username", context do
    assert Enum.sort(Enum.map(context.registration_responses, & &1.status)) == [200, 400]
    duplicate = Enum.find(context.registration_responses, &(&1.status == 400))
    assert json_response(duplicate, 400) == "username already taken"
    :ok
  end

  step "account {string} should await approval", %{args: [username]} do
    assert {:ok, %{active: false}} = Accounts.fetch_user(username)
    :ok
  end

  step "I log in via API as {string} with password {string}",
       %{args: [username, password]} = context do
    conn = IamClient.login(username, password)

    tokens = Map.get(context, :tokens, %{})

    {token, tokens} =
      if conn.status == 200 do
        %{"token" => t} = json_response(conn, 200)
        {t, Map.put(tokens, username, t)}
      else
        {Map.get(context, :token), tokens}
      end

    {:ok, Map.merge(context, %{last_conn: conn, token: token, tokens: tokens})}
  end

  step "the admin approves {string} via API", %{args: [username]} = context do
    admin = Map.fetch!(context, :admin)
    login = IamClient.login(admin.username, admin.password)
    assert %{"token" => admin_token} = json_response(login, 200)
    conn = IamClient.approve(admin_token, username)
    {:ok, Map.put(context, :last_conn, conn)}
  end

  step "I change my password via API from {string} to {string}",
       %{args: [current, new_pass]} = context do
    token = Map.fetch!(context, :token)
    conn = IamClient.change_password(token, current, new_pass)
    {:ok, Map.merge(context, %{last_conn: conn, last_password: new_pass})}
  end

  step "the API response status should be {int}", %{args: [status]} = context do
    assert context.last_conn.status == status
    :ok
  end

  step "the API response should include a token", context do
    assert %{"token" => token} = json_response(context.last_conn, 200)
    assert is_binary(token) and token != ""
    {:ok, Map.put(context, :token, token)}
  end

  step "unauthenticated admin approve of {string} via API", %{args: [username]} = context do
    conn =
      build_conn()
      |> Plug.Conn.put_req_header("content-type", "application/json")
      |> post("/admin/approve", %{"username" => username})

    {:ok, Map.put(context, :last_conn, conn)}
  end
end
