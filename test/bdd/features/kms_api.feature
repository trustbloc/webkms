#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@kms
Feature: KMS and crypto operations
  Background:
    Given Key Server is running on "localhost" port "8076"
      And SDS Server is running on "localhost" port "8081"
      And user has created a data vault on SDS Server for storing operational keys

  Scenario: User creates a key
    Given user has created an empty keystore on Key Server

    When  user makes an HTTP POST to "https://localhost:8076/kms/keystores/{keystoreID}/keys" to create "ED25519" key
    Then  user gets a response with HTTP status "201 Created"
     And  user gets a response with "Location" header with a valid URL

  Scenario: User exports a public key
    Given user has created a keystore with "ED25519" key on Key Server

    When  user makes an HTTP GET to "https://localhost:8076/kms/keystores/{keystoreID}/keys/{keyID}/export" to export public key
    Then  user gets a response with HTTP status "200 OK"
     And  user gets a response with non-empty "publicKey"

  Scenario: User signs a message and verifies a signature
    Given user has created a keystore with "ED25519" key on Key Server

    When  user makes an HTTP POST to "https://localhost:8076/kms/keystores/{keystoreID}/keys/{keyID}/sign" to sign "test message"
    Then  user gets a response with HTTP status "200 OK"
     And  user gets a response with non-empty "signature"

    When  user makes an HTTP POST to "https://localhost:8076/kms/keystores/{keystoreID}/keys/{keyID}/verify" to verify "signature" for "test message"
    Then  user gets a response with HTTP status "200 OK"
     And  user gets a response with no "errMsg"

  Scenario: User encrypts/decrypts a message
    Given user has created a keystore with "AES256GCM" key on Key Server

    When  user makes an HTTP POST to "https://localhost:8076/kms/keystores/{keystoreID}/keys/{keyID}/encrypt" to encrypt "test message"
    Then  user gets a response with HTTP status "200 OK"
     And  user gets a response with non-empty "cipherText"
     And  user gets a response with non-empty "nonce"

    When  user makes an HTTP POST to "https://localhost:8076/kms/keystores/{keystoreID}/keys/{keyID}/decrypt" to decrypt "cipherText"
    Then  user gets a response with HTTP status "200 OK"
     And  user gets a response with "plainText" with value "test message"

  Scenario: User computes/verifies MAC for data
    Given user has created a keystore with "HMACSHA256Tag256" key on Key Server

    When  user makes an HTTP POST to "https://localhost:8076/kms/keystores/{keystoreID}/keys/{keyID}/computemac" to compute MAC for "test data"
    Then  user gets a response with HTTP status "200 OK"
     And  user gets a response with non-empty "mac"

    When  user makes an HTTP POST to "https://localhost:8076/kms/keystores/{keystoreID}/keys/{keyID}/verifymac" to verify MAC "mac" for "test data"
    Then  user gets a response with HTTP status "200 OK"
     And  user gets a response with no "errMsg"
