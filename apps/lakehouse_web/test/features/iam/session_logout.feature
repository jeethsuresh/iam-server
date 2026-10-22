@api
Feature: Sign out of connected services
  Scenario: Central logout revokes app sessions without forgetting consent
    Given an approved user "apilogout" with password "password123"
    And two apps share my Gravitas browser login as "apilogout"
    When I sign out of that Gravitas browser login
    Then both services reject their old sessions and refresh tokens
