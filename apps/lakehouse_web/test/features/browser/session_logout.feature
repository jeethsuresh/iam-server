@browser
Feature: Sign out of Gravitas and connected services
  Scenario: The Settings sign-out button revokes all services linked to this login
    When I sign in through the browser as "browserlogout" with password "password123"
    And two test services are linked to the browser login for "browserlogout"
    And I sign out of Gravitas from Settings
    Then the connected test services are signed out but still connected
