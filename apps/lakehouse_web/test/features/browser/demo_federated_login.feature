@browser
Feature: Demo app federated login
  Users sign into the demo app via Lakehouse PKCE consent.

  Scenario: Demo login shows consent URLs then returns signed in
    Given an approved user "demouser" with password "password123"
    And I open the demo app
    When I start demo login as "@demouser:localhost"
    Then I should see the Lakehouse consent page with caller and callback URLs
    When I allow all chats on the consent page
    Then I should be signed in on the demo app as "demouser"
