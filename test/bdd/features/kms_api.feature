#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@kms
Feature: KMS operations

  Scenario: User creates a key
    Given Key Server is running on "localhost" port "8070"
      And User has created an empty keystore on the server
    When  User sends an HTTP POST to "https://{keystoreEndpoint}/keys" to create a key of "ED25519" type
    Then  User gets a response with HTTP 201 Created and Location with a valid URL for the newly created key

  Scenario: User signs a message and then verifies it
    Given Key Server is running on "localhost" port "8070"
      And User has created a keystore with a key of "ED25519" type on the server

    When  User sends an HTTP POST to "https://{keyEndpoint}/sign" to sign a message "test message"
    Then  User gets a response with HTTP 200 OK and a signature in the body

    When  User sends an HTTP POST to "https://{keyEndpoint}/verify" to verify a signature from the body
    Then  User gets a response with HTTP 200 OK and no error in the body

