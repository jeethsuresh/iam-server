@browser
Feature: Gravitas service dashboard
  Scenario: An administrator maintains the shared service catalog
    Given the bootstrap admin is available
    When I sign in through the browser as "admin" with password "adminpass"
    Then I should see my services dashboard
    When I add service "Fieldnotes" to the shared catalog

  Scenario: Connected apps reuse the existing Gravitas session across domains
    Given the demo app is in the shared service catalog
    When I sign in through the browser as "dashboarduser" with password "password123"
    And I launch the demo from my available services
    And I allow all chats on the consent page
    Then I should be signed in on the demo app as "dashboarduser"
    When I sign out of only the demo app and reopen it from connected services
    Then I should be signed in on the demo app as "dashboarduser"

  Scenario: The dashboard and groups navigation work on a phone
    Given I use a phone-sized browser
    When I sign in through the browser as "mobileuser" with password "password123"
    Then I should see my services dashboard
    And I can navigate to my groups on a phone
