@browser
Feature: Approve Private Store as the native account broker
  Scenario: The extra sign-in permission is explained before approval
    When I sign in through the browser as "browserbroker" with password "password123"
    And I review Private Store's native login request
    Then the native broker permission explains access to already approved apps
