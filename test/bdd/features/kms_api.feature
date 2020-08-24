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
    Then  User gets a response with HTTP 200 OK and a signature in the JSON body

    When  User sends an HTTP POST to "https://{keyEndpoint}/verify" to verify a signature from the body
    Then  User gets a response with HTTP 200 OK and no error in the body

  Scenario: User encrypts a message and then decrypts it
    Given Key Server is running on "localhost" port "8070"
      And User has created a keystore with a key of "AES256GCM" type on the server

    When  User sends an HTTP POST to "https://{keyEndpoint}/encrypt" to encrypt a message "test message"
    Then  User gets a response with HTTP 200 OK and a cipher text in the JSON body

    When  User sends an HTTP POST to "https://{keyEndpoint}/decrypt" to decrypt a cipher text from the body
    Then  User gets a response with HTTP 200 OK and a plain text "test message" in the JSON body

  Scenario: User computes MAC for data and then verifies it
    Given Key Server is running on "localhost" port "8070"
      And User has created a keystore with a key of "HMACSHA256Tag256" type on the server

    When  User sends an HTTP POST to "https://{keyEndpoint}/computemac" to compute MAC for data "test data"
    Then  User gets a response with HTTP 200 OK and MAC in the JSON body

    When  User sends an HTTP POST to "https://{keyEndpoint}/verifymac" to verify MAC for data
    Then  User gets a response with HTTP 200 OK and no error in the body
