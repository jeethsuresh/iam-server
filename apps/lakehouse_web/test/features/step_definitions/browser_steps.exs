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
    assert_has(context.session, Query.css(".chat-master__title", text: "Rooms"))
    :ok
  end

  step "I should see a sign-in error", context do
    assert_has(context.session, Query.css(".flash--error"))
    :ok
  end

  step "I create a room named {string} in the browser", %{args: [name]} = context do
    session =
      context.session
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

  step "I add member {string} in the browser", %{args: [username]} = context do
    ensure_approved_user(username, "password123")

    session =
      context.session
      |> fill_in(Query.css(".chat-detail__add-member-input"), with: username)
      |> click(Query.button("Add"))

    assert_has(session, Query.css(".chat-detail__member", text: username))
    {:ok, Map.put(context, :session, session)}
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
