@browser
Feature: Browser chat and settings
  Interactive users sign in and use the LiveView rooms UI.

  Scenario: Sign-in explains both local usernames and full addresses
    Given the identity domain "example.com" uses IAM at "https://iam.example.com"
    When I open the sign-in page
    Then the sign-in page explains both username formats for "example.com"

  Scenario: Sign in lands on services
    When I sign in through the browser as "alice" with password "password123"
    Then I should see my services dashboard

  Scenario: Sign in with a qualified identity
    When I sign in through the browser as "@qualified:localhost" with password "password123"
    Then I should see my services dashboard

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

  Scenario: Room info rename and membership
    Given an approved user "bob" with password "password123"
    When I sign in through the browser as "alice" with password "password123"
    And I create a room named "PanelRoom" in the browser
    And I open room "PanelRoom" in the browser
    And I open room info in the browser
    And I rename the room to "PanelRoom2" in the browser
    And I add member "bob" in the browser
    And I remove member "bob" in the browser

  Scenario: Leave room control lives in room info footer
    When I sign in through the browser as "alice" with password "password123"
    And I create a room named "LeaveSpot" in the browser
    And I open room "LeaveSpot" in the browser
    Then I should not see leave room in the chat header
    When I open room info in the browser
    Then I should see leave room in the room info panel

  Scenario: Upload image appears in chat and room info files
    When I sign in through the browser as "alice" with password "password123"
    And I create a room named "FilesRoom" in the browser
    And I open room "FilesRoom" in the browser
    And I upload chat image "chatshot.png" in the browser
    And room info uploaded files should include "chatshot.png"

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
