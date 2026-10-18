@api
Feature: Identity domain discovery
  Applications resolve @username:domain before starting federated login.

  Scenario: A separate identity domain advertises the IAM subdomain
    Given the identity domain "example.com" uses IAM at "https://iam.example.com"
    When I discover the identity "@alice:example.com"
    Then the API response status should be 200
    And the discovered IAM issuer should be "https://iam.example.com"

  @negative
  Scenario: A different identity domain is not claimed
    Given the identity domain "example.com" uses IAM at "https://iam.example.com"
    When I discover the identity "@alice:evil.example"
    Then the API response status should be 404
