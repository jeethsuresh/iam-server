@api @concurrency
Feature: Multi-user Matrix chat
  Separate users log in with their own tokens and exchange messages in a shared room.

  Scenario: Two users log in separately and chat back and forth
    Given an approved user "alice" with password "password123"
    And an approved user "bob" with password "password123"
    When I matrix-login as "alice"
    And I matrix-login as "bob"
    And I matrix-login as "alice"
    And I create a matrix room named "Chat"
    And "bob" joins the room via API
    When "alice" sends matrix message "hello bob" with txn "ab1"
    Then "bob" room messages should include "hello bob"
    And "bob" sync timeline should include "hello bob"
    When "bob" sends matrix message "hello alice" with txn "ba1"
    Then "alice" room messages should include "hello alice"
    And "alice" sync timeline should include "hello alice"
    And "bob" room messages should include "hello alice"
    And "alice" room messages should include "hello bob"

  Scenario: Three-message conversation is visible to both members
    Given an approved user "alice" with password "password123"
    And an approved user "bob" with password "password123"
    When I matrix-login as "alice"
    And I create a matrix room named "Thread"
    And "bob" joins the room via API
    And I matrix-login as "bob"
    When "alice" sends matrix message "ping" with txn "p1"
    And "bob" sends matrix message "pong" with txn "p2"
    And "alice" sends matrix message "ack" with txn "p3"
    Then "alice" room messages should include "ping"
    And "alice" room messages should include "pong"
    And "alice" room messages should include "ack"
    And "bob" room messages should include "ping"
    And "bob" room messages should include "pong"
    And "bob" room messages should include "ack"
