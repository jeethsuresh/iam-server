defmodule LakehouseWeb.RegistrationTest do
  use LakehouseWeb.ConnCase
  alias LakehouseIam.Accounts

  test "JSON registration cannot bypass the invitation key" do
    for key <- [nil, "", "wrong"] do
      conn =
        post(build_conn(), "/register", %{
          "username" => "inviteuser",
          "password" => "password123",
          "full_name" => "Invited User",
          "registration_key" => key
        })

      assert json_response(conn, 403) == "A valid registration key is required."
      refute Accounts.user_exists?("inviteuser")
    end
  end

  test "correct key creates a pending account without disclosing the key" do
    conn =
      post(build_conn(), "/register", %{
        "username" => "inviteuser",
        "password" => "password123",
        "full_name" => "Invited User",
        "registration_key" => "test-invitation-key"
      })

    assert json_response(conn, 200)["message"] =~ "administrator must approve"
    assert {:ok, %{active: false, full_name: "Invited User"}} = Accounts.fetch_user("inviteuser")
    refute conn.resp_body =~ "test-invitation-key"
  end

  test "a valid key cannot bypass full name validation" do
    for full_name_params <- [%{}, %{"full_name" => " \t"}] do
      params = %{
        "username" => "blankname",
        "password" => "password123",
        "registration_key" => "test-invitation-key"
      }

      conn = post(build_conn(), "/register", Map.merge(params, full_name_params))
      assert json_response(conn, 400) == "Full name can't be blank"
      refute Accounts.user_exists?("blankname")
    end
  end

  test "registration form requires a full name and does not embed the invitation key" do
    conn = get(build_conn(), "/register")
    html = html_response(conn, 200)
    assert html =~ ~r/<input[^>]*name="full_name"[^>]*\brequired\b/
    assert html =~ ~s(name="registration_key")
    refute conn.resp_body =~ "test-invitation-key"
  end
end
