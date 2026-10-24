@api
Feature: Matrix client-server room lifecycle
  Users create rooms, exchange messages, sync, and leave.

  Scenario: Create join send sync leave
    Given an approved user "alice" with password "password123"
    And an approved user "bob" with password "password123"
    When I matrix-login as "alice"
    And I create a public matrix room named "General"
    And "bob" joins the room via API
    And I send matrix message "hello matrix"
    Then room messages should include "hello matrix"
    And "alice" sync should include the room
    And "bob" sync should include the room
    When "bob" leaves the room via API
    Then "bob" sync should not include the room
    And "alice" sync should include the room

  @negative
  Scenario: Unauthenticated sync is rejected
    When unauthenticated matrix sync
    Then the API response status should be 401

  @negative
  Scenario: User without send permission cannot send
    Given an approved user "alice" with password "password123"
    And an approved user "bob" with password "password123"
    When I matrix-login as "alice"
    And I create a public matrix room named "Locked"
    And "bob" joins the room via API
    And user "bob" has no send permission
    When "bob" attempts to send matrix message "nope"
    Then the API response status should be 403

  @concurrency
  Scenario: Two members send messages in one room
    Given an approved user "alice" with password "password123"
    And an approved user "bob" with password "password123"
    When I matrix-login as "alice"
    And I create a public matrix room named "Busy"
    And "bob" joins the room via API
    And I matrix-login as "alice"
    And two users send distinct messages in the same room
    Then room messages should include "concurrent-alice"
    And room messages should include "concurrent-bob"
