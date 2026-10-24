@api
Feature: Room media and membership via Matrix API
  Users upload media, send file messages, edit room metadata, and creators remove members.

  Scenario: Upload image media and send as room message
    Given an approved user "alice" with password "password123"
    When I matrix-login as "alice"
    And I create a matrix room named "MediaRoom"
    And I upload media file "shot.png" as image via API
    And I send the uploaded media as an image message
    Then room messages should include "shot.png"
    And I can download the uploaded media via API

  Scenario: Set room name and avatar via state API
    Given an approved user "alice" with password "password123"
    When I matrix-login as "alice"
    And I create a matrix room named "MetaRoom"
    And I set the room name via API to "MetaRoom Renamed"
    Then the API response status should be 200
    And I upload media file "avatar.png" as image via API
    And I set the room avatar to the uploaded media via API
    Then the API response status should be 200

  Scenario: Creator removes member; non-creator cannot
    Given an approved user "alice" with password "password123"
    And an approved user "bob" with password "password123"
    And an approved user "carol" with password "password123"
    When I matrix-login as "alice"
    And I create a public matrix room named "KickRoom"
    And "bob" joins the room via API
    And "carol" joins the room via API
    And I matrix-login as "bob"
    And "bob" attempts to kick "carol" from the room via API
    Then the API response status should be 403
    When I matrix-login as "alice"
    And I kick "carol" from the room via API
    Then the API response status should be 200
    And "carol" sync should not include the room
