@browser @river_matrix_access
Feature: River requires full Matrix access
  Scenario: Matrix client consent covers current and future spaces and conversations
    When I sign in through the browser as "rivermatrixbrowser" with password "password123"
    And I review River's full Matrix login request
    Then River requires access to all Matrix spaces and conversations
