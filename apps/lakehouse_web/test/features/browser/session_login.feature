@browser
Feature: Application login through the existing Gravitas session
  Scenario: Browser access renews without asking for the password again
    Given an approved user "browserrenew" with password "password123"
    When I open the groups page while signed out
    And my browser access expires but its refresh session remains valid
    And I reopen the groups page without signing in again
    Then I should be on the rooms page

  Scenario: An app reuses the base login without asking for a username
    When I sign in through the browser as "sessionreuse" with password "password123"
    And I open a username-free application login
    Then I should see the Lakehouse consent page with caller and callback URLs

  Scenario: Signing in resumes the protected page the visitor opened
    Given an approved user "browserreturn" with password "password123"
    When I open the groups page while signed out
    And I sign in again on the current form as "browserreturn"
    Then I should be on the rooms page

  Scenario: A revoked session gives a clear sign-in prompt and keeps the destination
    Given an approved user "browserexpiry" with password "password123"
    When I open the groups page while signed out
    And I sign in with an already expired session as "browserexpiry"
    Then I should see the friendly expired-session prompt
    When I sign in again on the current form as "browserexpiry"
    Then I should be on the rooms page

  Scenario: Application registration retains the return flow through approval
    Given the bootstrap admin is available
    When I open application registration
    And I register from the application flow as "pendingreturn"
    Then I should see registration awaiting approval
    And the application sign-in form retains its request
    When the admin approves "pendingreturn" via API
    And I complete the application sign-in as "pendingreturn"
    Then I should see the Lakehouse consent page with caller and callback URLs
