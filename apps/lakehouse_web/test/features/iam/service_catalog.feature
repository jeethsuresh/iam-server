@api
Feature: Shared service catalog
  Scenario: Administrator additions are visible to all account holders
    Given the bootstrap admin is available
    And an approved user "catalogviewer" with password "password123"
    When the administrator catalogs the service with sign-in URL "https://notes.example.com/auth/gravitas/start"
    Then the API response status should be 201
    When I log in via API as "catalogviewer" with password "password123"
    Then the shared catalog should include "Notes"

  @negative
  Scenario: A member cannot add a service
    Given an approved user "catalogmember" with password "password123"
    When I log in via API as "catalogmember" with password "password123"
    And I catalog the service with sign-in URL "https://notes.example.com/login"
    Then the API response status should be 403

  @negative
  Scenario: Service login cannot point at another origin
    Given the bootstrap admin is available
    When the administrator catalogs the service with sign-in URL "https://other.example.com/login"
    Then the API response status should be 422
