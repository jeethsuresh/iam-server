@api
Feature: IAM registration and login
  Users register, admins approve, and login returns a JWT.

  Scenario: Pending user is approved and can log in
    Given the bootstrap admin is available
    And a pending user "carol" with password "password123"
    When the admin approves "carol" via API
    Then the API response status should be 200
    When I log in via API as "carol" with password "password123"
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
