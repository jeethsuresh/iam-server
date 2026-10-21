@api
Feature: IAM registration and login
  Users register, admins approve, and login returns a JWT.

  Scenario: Invitation key permits signup for administrator approval
    When I register via API as "invited" with password "password123" and key "test-invitation-key"
    Then the API response status should be 200
    And account "invited" should await approval

  @negative
  Scenario: Missing invitation key blocks signup
    When I register via API as "uninvited" with password "password123"
    Then the API response status should be 403
    And account "uninvited" should not exist

  @negative @concurrency
  Scenario: Overlapping registrations create one pending account without a server error
    When I submit overlapping API registrations for "racesignup" with key "test-invitation-key"
    Then one registration succeeds and the other reports a duplicate username
    And account "racesignup" should await approval

  @negative
  Scenario: Wrong invitation key blocks signup
    When I register via API as "uninvited" with password "password123" and key "wrong"
    Then the API response status should be 403
    And account "uninvited" should not exist

  Scenario: Pending user is approved and can log in
    Given the bootstrap admin is available
    And a pending user "carol" with password "password123"
    When the admin approves "carol" via API
    Then the API response status should be 200
    When I log in via API as "carol" with password "password123"
    Then the API response status should be 200
    And the API response should include a token

  Scenario: Local usernames and full addresses both sign in to the local account
    Given the identity domain "example.com" uses IAM at "https://iam.example.com"
    And an approved user "localname" with password "password123"
    When I log in via API as "localname" with password "password123"
    Then the API response status should be 200
    And the API response should include a token
    When I log in via API as "@localname:example.com" with password "password123"
    Then the API response status should be 200
    And the API response should include a token

  @negative
  Scenario: Invalid login is rejected
    Given an approved user "dave" with password "password123"
    When I log in via API as "dave" with password "wrong-password"
    Then the API response status should be 401

  @negative
  Scenario: Unauthenticated admin approve is rejected
    When unauthenticated admin approve of "nobody" via API
    Then the API response status should be 401

  Scenario: Password change via API
    Given an approved user "erin" with password "password123"
    When I log in via API as "erin" with password "password123"
    Then the API response should include a token
    When I change my password via API from "password123" to "password456"
    Then the API response status should be 200
    When I log in via API as "erin" with password "password123"
    Then the API response status should be 401
    When I log in via API as "erin" with password "password456"
    Then the API response status should be 200
