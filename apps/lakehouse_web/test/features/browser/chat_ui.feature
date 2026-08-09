@browser
Feature: Browser chat and settings
  Interactive users sign in and use the LiveView rooms UI.

  Scenario: Sign in lands on rooms
    When I sign in through the browser as "alice" with password "password123"
    Then I should be on the rooms page

  @negative
  Scenario: Invalid browser sign-in shows an error
    Given an approved user "alice" with password "password123"
    When I open the sign-in page
    And I sign in through the browser as "alice" with password "bad-password"
    Then I should see a sign-in error

  Scenario: Create room and send a message
    When I sign in through the browser as "alice" with password "password123"
    And I create a room named "Lounge" in the browser
    And I open room "Lounge" in the browser
    And I send browser message "hi from wallaby"
    Then I should be on the rooms page

  Scenario: Add member by username
    Given an approved user "bob" with password "password123"
    When I sign in through the browser as "alice" with password "password123"
    And I create a room named "Invite" in the browser
    And I open room "Invite" in the browser
    And I add member "bob" in the browser

  Scenario: Change password in settings
    When I sign in through the browser as "fran" with password "password123"
    And I open settings in the browser
    And I change password in the browser from "password123" to "password999"

  Scenario: Admin approves pending user from settings
    Given the bootstrap admin is available
    And a pending browser user "gina" with password "password123"
    When I sign in through the browser as "admin" with password "adminpass"
    And I open settings in the browser
    And I approve "gina" from settings in the browser
