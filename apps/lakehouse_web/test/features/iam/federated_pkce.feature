@api
Feature: Federated PKCE app login
  Third-party apps use Authorization Code + PKCE without client secrets.

  Scenario: Register PKCE session returns sessionID without publicKey
    Given an approved user "pkcealice" with password "password123"
    When I register a PKCE backend session for "pkcealice" at origin "http://127.0.0.1:4102"
    Then the API response status should be 200
    And the backend register response has a sessionID
    And the backend register response has no publicKey

  @negative
  Scenario: Cross-origin caller and redirect are rejected
    Given an approved user "pkcebob" with password "password123"
    When I register a PKCE backend session for "pkcebob" with mismatched origins
    Then the API response status should be 400
