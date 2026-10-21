@api
Feature: Silent application sign-in
  Scenario: A signed-out browser returns to the app without showing login
    When I request silent application login without a base session
    Then the app callback reports "login_required" with its original state

  Scenario: New application consent is never silently granted
    Given an approved user "silentuser" with password "password123"
    When I request silent application login with the base session for "silentuser"
    Then the app callback reports "consent_required" with its original state
