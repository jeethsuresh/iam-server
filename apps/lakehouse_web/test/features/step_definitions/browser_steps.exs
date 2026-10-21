defmodule LakehouseWeb.Bdd.BrowserSteps do
  use Cucumber.StepDefinition
  import ExUnit.Assertions
  import Wallaby.Browser
  alias Wallaby.Query

  alias LakehouseIam.Accounts
  alias LakehouseWeb.MatrixFixtures

  step "I open the sign-in page", context do
    session = context.session |> visit("/")
    {:ok, Map.put(context, :session, session)}
  end

  step "the sign-in page explains both username formats for {string}",
       %{args: [domain]} = context do
    assert_has(context.session, Query.css("#username-help", text: domain))
    assert_has(context.session, Query.css("#username-help", text: "@user:#{domain}"))
    :ok
  end

  step "I sign up in the browser as {string} with key {string}",
       %{args: [username, key]} = context do
    session =
      context.session
      |> visit("/register")
      |> fill_in(Query.text_field("Username"), with: username)
      |> fill_in(Query.text_field("Password"), with: "password123")
      |> fill_in(Query.text_field("Registration key"), with: key)
      |> click(Query.button("Register"))

    # Wait for the server response before the following account assertions.
    assert_has(session, Query.css(".flash"))
    {:ok, Map.put(context, :session, session)}
  end

  step "I should see registration awaiting approval", context do
    assert_has(context.session, Query.css(".flash--info", text: "administrator must approve"))
    :ok
  end

  step "I should see a registration key error", context do
    assert_has(
      context.session,
      Query.css(".flash--error", text: "A valid registration key is required.")
    )

    :ok
  end

  step "I should see a duplicate username error", context do
    assert_has(context.session, Query.css(".flash--error", text: "username already taken"))
    :ok
  end

  step "I sign in through the browser as {string} with password {string}",
       %{args: [username, password]} = context do
    ensure_approved_user(username, password)

    session =
      context.session
      |> visit("/")
      |> fill_in(Query.text_field("Username"), with: username)
      |> fill_in(Query.text_field("Password"), with: password)
      |> click(Query.button("Sign in"))

    {:ok, Map.put(context, :session, session)}
  end

  step "I should be on the rooms page", context do
    assert_has(context.session, Query.css(".chat-master__title", text: "Groups"))
    :ok
  end

  step "I should see a sign-in error", context do
    assert_has(context.session, Query.css(".flash--error"))
    :ok
  end

  step "I create a room named {string} in the browser", %{args: [name]} = context do
    session =
      context.session
      |> click(Query.link("Groups"))
      |> assert_has(Query.css(".chat-master__create"))
      |> fill_in(Query.css(".chat-master__input"), with: name)
      |> click(Query.css(".chat-master__create-btn"))

    assert_has(session, Query.css(".chat-room-list__name", text: name))
    {:ok, Map.merge(context, %{session: session, room_name: name})}
  end

  step "I open room {string} in the browser", %{args: [name]} = context do
    session = click(context.session, Query.css(".chat-room-list__link", text: name))
    assert_has(session, Query.css(".chat-detail__title", text: name))
    {:ok, Map.put(context, :session, session)}
  end

  step "I send browser message {string}", %{args: [body]} = context do
    session =
      context.session
      |> fill_in(Query.css("#message-composer"), with: body)
      |> click(Query.button("Send"))

    assert_has(session, Query.css(".chat-message__body", text: body))
    {:ok, Map.merge(context, %{session: session, last_message: body})}
  end

  step "I open room info in the browser", context do
    session =
      context.session
      |> click(Query.css("#room-info-open"))
      |> assert_has(Query.css("#room-info-panel"))

    {:ok, Map.put(context, :session, session)}
  end

  step "I should not see leave room in the chat header", context do
    refute_has(context.session, Query.css(".chat-detail__header #leave-room-btn"))
    refute_has(context.session, Query.css(".chat-detail__header .chat-detail__leave"))
    :ok
  end

  step "I should see leave room in the room info panel", context do
    assert_has(context.session, Query.css("#room-info-panel #leave-room-btn", text: "Leave room"))
    :ok
  end

  step "I add member {string} in the browser", %{args: [username]} = context do
    ensure_approved_user(username, "password123")

    session =
      context.session
      |> then(fn s ->
        if has?(s, Query.css("#room-info-panel")) do
          s
        else
          s
          |> click(Query.css("#room-info-open"))
          |> assert_has(Query.css("#room-info-panel"))
        end
      end)
      |> fill_in(Query.css(".chat-detail__add-member-input"), with: username)
      |> click(Query.css("#room-info-panel button", text: "Add"))

    assert_has(session, Query.css("#room-info-panel .chat-detail__member", text: username))
    {:ok, Map.put(context, :session, session)}
  end

  step "I rename the room to {string} in the browser", %{args: [name]} = context do
    session =
      context.session
      |> then(fn s ->
        if has?(s, Query.css("#room-info-panel")) do
          s
        else
          click(s, Query.css("#room-info-open"))
        end
      end)
      |> assert_has(Query.css("#room-info-panel"))
      |> fill_in(Query.css("#room-name-input"), with: name)
      |> click(Query.css("#room-name-form button", text: "Save"))

    assert_has(session, Query.css(".chat-detail__title", text: name))
    {:ok, Map.merge(context, %{session: session, room_name: name})}
  end

  step "I remove member {string} in the browser", %{args: [username]} = context do
    session =
      context.session
      |> then(fn s ->
        if has?(s, Query.css("#room-info-panel")) do
          s
        else
          click(s, Query.css("#room-info-open"))
        end
      end)
      |> assert_has(Query.css("#room-info-panel"))

    session =
      find(session, Query.css("#room-info-panel .room-info__member", text: username), fn el ->
        click(el, Query.css(".room-info__remove"))
      end)

    refute_has(session, Query.css("#room-info-panel .chat-detail__member", text: username))
    {:ok, Map.put(context, :session, session)}
  end

  step "I upload chat image {string} in the browser", %{args: [filename]} = context do
    path = write_temp_png(filename)

    session =
      context.session
      |> attach_file(Query.css("#chat-attach input[type=file]"), path: path)

    # LiveView auto-upload + ImageMagick compress can take a moment.
    Process.sleep(3000)
    assert_has(session, Query.css(".chat-message__image", count: 1))

    File.rm(path)
    {:ok, Map.put(context, :session, session)}
  end

  step "room info uploaded files should include {string}", %{args: [filename]} = context do
    session =
      context.session
      |> then(fn s ->
        if has?(s, Query.css("#room-info-panel")) do
          s
        else
          click(s, Query.css("#room-info-open"))
        end
      end)
      |> assert_has(Query.css("#room-uploaded-files a", text: filename))

    {:ok, Map.put(context, :session, session)}
  end

  defp write_temp_png(filename) do
    path = Path.join(System.tmp_dir!(), "wallaby-#{filename}")

    {_, 0} =
      System.cmd("magick", ["-size", "240x180", "plasma:fractal", path], stderr_to_stdout: true)

    path
  end

  step "I open settings in the browser", context do
    session = click(context.session, Query.link("Settings"))
    assert_has(session, Query.css(".settings-page"))
    {:ok, Map.put(context, :session, session)}
  end

  step "I change password in the browser from {string} to {string}",
       %{args: [current, new_pass]} = context do
    session =
      context.session
      |> fill_in(Query.text_field("Current password"), with: current)
      |> fill_in(Query.text_field("New password"), with: new_pass)
      |> fill_in(Query.text_field("Confirm new password"), with: new_pass)
      |> click(Query.button("Update password"))

    assert_has(session, Query.css(".flash--info"))
    {:ok, Map.put(context, :session, session)}
  end

  step "a pending browser user {string} with password {string}",
       %{args: [username, password]} = context do
    MatrixFixtures.ensure_rbac!()
    {:ok, principal} = Accounts.register_user(username, password, approve: false)
    refute principal.active
    {:ok, Map.put(context, :pending_browser_user, username)}
  end

  step "I approve {string} from settings in the browser", %{args: [username]} = context do
    session =
      context.session
      |> assert_has(Query.css(".settings-pending__item", text: username))
      |> click(Query.button("Approve"))

    assert_has(session, Query.css(".flash--info"))
    {:ok, Map.put(context, :session, session)}
  end

  step "I open the demo app", context do
    Application.put_env(:lakehouse_iam, :relaxed_callback_urls, true)

    demo_port =
      Application.get_env(:lakehouse_app_demo, LakehouseAppDemo.Endpoint)[:url][:port] || 4102

    session = context.session |> visit("http://127.0.0.1:#{demo_port}/")
    assert_has(session, Query.css("h1", text: "Lakehouse App Demo"))
    {:ok, Map.put(context, :session, session)}
  end

  step "I start demo login as {string}", %{args: [username_at]} = context do
    session =
      context.session
      |> fill_in(Query.css("input[name=username]"), with: username_at)
      |> click(Query.button("Continue"))

    {:ok, Map.put(context, :session, session)}
  end

  step "I should see the Lakehouse consent page with caller and callback URLs", context do
    # May land on login first
    session = context.session

    session =
      if has?(session, Query.button("Sign in")) do
        password =
          Map.get(context, :users, %{})
          |> Map.get("demouser", "password123")

        session
        |> fill_in(Query.text_field("Password"), with: password)
        |> click(Query.button("Sign in"))
      else
        session
      end

    assert_has(session, Query.css("h1", text: "Authorize application"))
    page = page_source(session)
    assert page =~ "Caller URL"
    assert page =~ "Callback URL"
    {:ok, Map.put(context, :session, session)}
  end

  step "I allow all chats on the consent page", context do
    session =
      context.session
      |> then(fn s ->
        if has?(s, Query.css("input[name=all_rooms]")) do
          click(s, Query.css("input[name=all_rooms]"))
        else
          s
        end
      end)
      |> click(Query.button("Allow"))

    {:ok, Map.put(context, :session, session)}
  end

  step "I should be signed in on the demo app as {string}", %{args: [name]} = context do
    assert_has(context.session, Query.css("h1", text: "Signed in"))
    assert_has(context.session, Query.css("strong", text: name))
    :ok
  end

  step "I should see my services dashboard", context do
    assert_has(context.session, Query.css("h1", text: "A little more connected."))
    assert_has(context.session, Query.css("#connected-heading", text: "Connected services"))
    assert_has(context.session, Query.css("#available-heading", text: "Available services"))
    :ok
  end

  step "I use a phone-sized browser", context do
    session = resize_window(context.session, 390, 844)
    {:ok, Map.put(context, :session, session)}
  end

  step "I can navigate to my groups on a phone", context do
    session = context.session |> click(Query.link("Groups"))
    assert_has(session, Query.css(".chat-master__title", text: "Groups"))
    # Capture the responsive app after navigation, including the persistent global menu.
    take_screenshot(session, name: "gravitas-mobile-groups")
    {:ok, Map.put(context, :session, session)}
  end

  step "I add service {string} to the shared catalog", %{args: [name]} = context do
    session =
      context.session
      |> click(Query.link("Service catalog"))
      |> fill_in(Query.text_field("Service name"), with: name)
      |> fill_in(Query.css("#service-home"), with: "https://notes.example.com/")
      |> fill_in(Query.css("#service-login"),
        with: "https://notes.example.com/auth/gravitas/start"
      )
      |> click(Query.button("Add service"))

    assert_has(session, Query.css(".catalog-row", text: name))
    session = session |> click(Query.link("Services"))
    assert_has(session, Query.css("#available-services", text: name))
    {:ok, Map.put(context, :session, session)}
  end

  step "the demo app is in the shared service catalog", _context do
    Application.put_env(:lakehouse_iam, :relaxed_callback_urls, true)
    port = Application.get_env(:lakehouse_app_demo, LakehouseAppDemo.Endpoint)[:url][:port]

    {:ok, _} =
      LakehouseIam.Apps.Catalog.create(%{
        name: "Demo",
        home_url: "http://127.0.0.1:#{port}/",
        login_url: "http://127.0.0.1:#{port}/auth/gravitas/start"
      })

    :ok
  end

  step "I launch the demo from my available services", context do
    session = context.session |> click(Query.css("#available-services a[data-service=Demo]"))
    # The existing Gravitas session should go directly to consent, without a password form.
    assert_has(session, Query.css("h1", text: "Authorize application"))
    refute_has(session, Query.button("Sign in"))
    {:ok, Map.put(context, :session, session)}
  end

  step "I sign out of only the demo app and reopen it from connected services", context do
    port = Application.get_env(:lakehouse_app_demo, LakehouseAppDemo.Endpoint)[:url][:port]
    session = context.session |> visit("http://127.0.0.1:#{port}/logout")
    assert_has(session, Query.css("h1", text: "Lakehouse App Demo"))
    session = session |> visit("/dashboard")
    assert_has(session, Query.css("#connected-services", text: "Demo"))
    session = session |> click(Query.css("#connected-services a[data-service=Demo]"))
    assert_has(session, Query.css("h1", text: "Signed in"))
    refute_has(session, Query.button("Allow"))
    {:ok, Map.put(context, :session, session)}
  end

  defp ensure_approved_user(username, password) do
    MatrixFixtures.ensure_rbac!()
    admin = Application.fetch_env!(:lakehouse_iam, :admin_username)

    if Accounts.normalize_username(username) == Accounts.normalize_username(admin) do
      _ = LakehouseIam.Bootstrap.run()
      :ok
    else
      case Accounts.fetch_user(Accounts.normalize_username(username)) do
        {:ok, _} ->
          :ok

        :error ->
          _ = MatrixFixtures.user_fixture(username)

          if password != "password123" do
            :ok = Accounts.change_own_password(username, "password123", password, password)
          end

          :ok
      end
    end
  end
end
