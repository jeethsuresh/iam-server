@browser
Feature: Application login through the existing Gravitas session
  Scenario: An app reuses the base login without asking for a username
    When I sign in through the browser as "sessionreuse" with password "password123"
    And I open a username-free application login
    Then I should see the Lakehouse consent page with caller and callback URLs

  Scenario: Application registration retains the return flow through approval
    Given the bootstrap admin is available
    When I open application registration
    And I register from the application flow as "pendingreturn"
    Then I should see registration awaiting approval
    And the application sign-in form retains its request
    When the admin approves "pendingreturn" via API
    And I complete the application sign-in as "pendingreturn"
    Then I should see the Lakehouse consent page with caller and callback URLs
