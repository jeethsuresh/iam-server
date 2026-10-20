defmodule LakehouseWeb.RegistrationTest do
  use LakehouseWeb.ConnCase
  alias LakehouseIam.Accounts

  test "JSON registration cannot bypass the invitation key" do
    for key <- [nil, "", "wrong"] do
      conn =
        post(build_conn(), "/register", %{
          "username" => "inviteuser",
          "password" => "password123",
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
        "registration_key" => "test-invitation-key"
      })

    assert json_response(conn, 200)["message"] =~ "administrator must approve"
    assert {:ok, %{active: false}} = Accounts.fetch_user("inviteuser")
    refute conn.resp_body =~ "test-invitation-key"
  end

  test "registration form does not embed the invitation key" do
    conn = get(build_conn(), "/register")
    assert html_response(conn, 200) =~ ~s(name="registration_key")
    refute conn.resp_body =~ "test-invitation-key"
  end
end
