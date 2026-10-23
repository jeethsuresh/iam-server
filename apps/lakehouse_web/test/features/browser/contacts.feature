@browser
Feature: Shared Gravitas contacts
  Scenario: Contact requests need acceptance and become River friends without a second request
    Given an approved user "contactbrowserbob" with password "password123"
    When I sign in through the browser as "contactbrowseralice" with password "password123"
    And I send a Gravitas contact request to "contactbrowserbob" in the browser
    Then the Gravitas contact request is still pending
    When I sign out from the contacts page
    And I sign in through the browser as "contactbrowserbob" with password "password123"
    And I accept the Gravitas contact request from "contactbrowseralice" in the browser
    Then those contacts become River friends after approving River contacts access
