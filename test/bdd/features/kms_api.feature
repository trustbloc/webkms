#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@kms
Feature: Key management operations
  Background:
    Given Key server is running on "localhost" port "4466"
      And Auth key server is running on "localhost" port "4455"
      And Auth server is running on "localhost" port "8070"
      And EDV is running on "localhost" port "8081"
      And "Alice" wallet has stored secret on Auth server
      And "Bob" wallet has stored secret on Auth server
      And "Alice" has created a data vault on EDV for storing keys
      And "Bob" has created a data vault on EDV for storing keys

  Scenario: User creates a keystore
    When  user makes an HTTP POST to "https://localhost:4466/v1/keystore" to create a keystore
    Then  user gets a response with HTTP status "201 Created" and with valid "Location" and "X-RootCapability" headers

  Scenario: User creates a key
    Given "Alice" has created an empty keystore on key server

    When  "Alice" makes an HTTP POST to "https://localhost:4466/v1/keystore/{keystoreID}/key" to create "ED25519" key
    Then  "Alice" gets a response with HTTP status "201 Created"
     And  "Alice" gets a response with "Location" header with a valid URL
