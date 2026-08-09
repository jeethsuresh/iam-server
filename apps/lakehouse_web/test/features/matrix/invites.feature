@api
Feature: Matrix invites and sync sections
  Members can invite users; invitees see rooms.invite until they join.

  Scenario: Invite then join via Matrix API
    Given an approved user "alice" with password "password123"
    And an approved user "bob" with password "password123"
    When I matrix-login as "alice"
    And I create a matrix room named "InviteRoom"
    And I invite "@bob:localhost" to the room via API
    And I matrix-login as "bob"
    Then "bob" sync invite section should include the room
    When "bob" joins the room via API
    Then "bob" sync should include the room
    And "bob" sync invite section should not include the room
