@api
Feature: Native applications use a trusted Gravitas account broker
  Scenario: Broker login never survives central logout or recreates forgotten consent
    Given an approved user "apibroker" with password "password123"
    And Private Store has an explicitly authorized native broker login for "apibroker"
    When Private Store requests an unapproved native service login
    Then native service consent is required and no grant is created
    When that native service is approved and receives a broker login
    And I sign out of the broker's Gravitas browser login
    Then the native service and broker refresh cannot resume the revoked login
