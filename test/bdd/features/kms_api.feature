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
      And AuthZ Key Server is running on "localhost" port "8077"
      And Hub Auth is running on "localhost" port "8070"
      And EDV is running on "localhost" port "8081"
      And "Alice" wallet has stored secret on Hub Auth
      And "Bob" wallet has stored secret on Hub Auth
      And "Alice" has created a data vault on EDV for storing keys
      And "Bob" has created a data vault on EDV for storing keys

  Scenario: User creates a key
    Given "Alice" has created an empty keystore on Key Server

    When  "Alice" makes an HTTP POST to "https://localhost:8076/kms/keystores/{keystoreID}/keys" to create "ED25519" key
    Then  "Alice" gets a response with HTTP status "201 Created"
     And  "Alice" gets a response with "Location" header with a valid URL

  Scenario: User exports a public key
    Given "Bob" has created a keystore with "ED25519" key on Key Server

    When  "Bob" makes an HTTP GET to "https://localhost:8076/kms/keystores/{keystoreID}/keys/{keyID}/export" to export public key
    Then  "Bob" gets a response with HTTP status "200 OK"
     And  "Bob" gets a response with non-empty "publicKey"

  Scenario: User signs a message and verifies a signature
    Given "Alice" has created a keystore with "ED25519" key on Key Server

    When  "Alice" makes an HTTP POST to "https://localhost:8076/kms/keystores/{keystoreID}/keys/{keyID}/sign" to sign "test message"
    Then  "Alice" gets a response with HTTP status "200 OK"
     And  "Alice" gets a response with non-empty "signature"

    When  "Alice" makes an HTTP POST to "https://localhost:8076/kms/keystores/{keystoreID}/keys/{keyID}/verify" to verify "signature" for "test message"
    Then  "Alice" gets a response with HTTP status "200 OK"
     And  "Alice" gets a response with no "errMessage"

  Scenario: User encrypts/decrypts a message
    Given "Bob" has created a keystore with "AES256GCM" key on Key Server

    When  "Bob" makes an HTTP POST to "https://localhost:8076/kms/keystores/{keystoreID}/keys/{keyID}/encrypt" to encrypt "test message"
    Then  "Bob" gets a response with HTTP status "200 OK"
     And  "Bob" gets a response with non-empty "cipherText"
     And  "Bob" gets a response with non-empty "nonce"

    When  "Bob" makes an HTTP POST to "https://localhost:8076/kms/keystores/{keystoreID}/keys/{keyID}/decrypt" to decrypt "cipherText"
    Then  "Bob" gets a response with HTTP status "200 OK"
     And  "Bob" gets a response with "plainText" with value "test message"

  Scenario: User computes/verifies MAC for data
    Given "Alice" has created a keystore with "HMACSHA256Tag256" key on Key Server

    When  "Alice" makes an HTTP POST to "https://localhost:8076/kms/keystores/{keystoreID}/keys/{keyID}/computemac" to compute MAC for "test data"
    Then  "Alice" gets a response with HTTP status "200 OK"
     And  "Alice" gets a response with non-empty "mac"

    When  "Alice" makes an HTTP POST to "https://localhost:8076/kms/keystores/{keystoreID}/keys/{keyID}/verifymac" to verify MAC "mac" for "test data"
    Then  "Alice" gets a response with HTTP status "200 OK"
     And  "Alice" gets a response with no "errMessage"

  Scenario: User A wraps key for User B, User B successfully unwraps it (Anoncrypt)
    Given "Alice" has created a keystore with "ECDH256KWAES256GCM" key on Key Server
      And "Bob" has created a keystore with "ECDH256KWAES256GCM" key on Key Server
      And "Alice" has a public key of "Bob"

    When  "Alice" makes an HTTP POST to "https://localhost:8076/kms/keystores/{keystoreID}/wrap" to wrap "testCEK" for "Bob"
    Then  "Alice" gets a response with HTTP status "200 OK"
     And  "Alice" gets a response with non-empty "wrappedKey"

    When  "Bob" makes an HTTP POST to "https://localhost:8076/kms/keystores/{keystoreID}/keys/{keyID}/unwrap" to unwrap "wrappedKey" from "Alice"
    Then  "Bob" gets a response with HTTP status "200 OK"
     And  "Bob" gets a response with content of "testCEK" key
