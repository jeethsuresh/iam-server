@browser
Feature: Invitation-only account registration
  New accounts require a registration key in the browser and on the server.

  Scenario: Valid registration key creates an account awaiting approval
    When I sign up in the browser as "browserinvite" with key "test-invitation-key"
    Then account "browserinvite" should await approval
    And I should see registration awaiting approval

  @negative
  Scenario: Incorrect registration key cannot create an account
    When I sign up in the browser as "browserreject" with key "wrong"
    Then I should see a registration key error
    And account "browserreject" should not exist

  @negative
  Scenario: Resubmitting a pending account shows a duplicate username message
    When I sign up in the browser as "browserrepeat" with key "test-invitation-key"
    And I sign up in the browser as "browserrepeat" with key "test-invitation-key"
    Then I should see a duplicate username error
    And account "browserrepeat" should await approval
