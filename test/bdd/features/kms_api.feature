#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@kms
Feature: KMS and crypto operations
  Background:
    Given Key Server is running on "localhost" port "4466"
      And Hub Auth is running on "auth.trustbloc.local" port "8070"
      And "Alice" has logged into auth server
      And "Bob" has logged into auth server
      And "Alice" has created a profile on auth server
      And "Bob" has created a profile on auth server

  Scenario: User creates a key
    Given "Alice" has created an empty keystore on Key Server

    When  "Alice" makes an HTTP POST to "https://localhost:4466/v1/keystores/{keystoreID}/keys" to create "ED25519" key
    Then  "Alice" gets a response with HTTP status "200 OK"
     And  "Alice" gets a response with non-empty "key_url"

  Scenario: User creates multiple keys with parallel requests
    Given "Alice" has created an empty keystore on Key Server

    When  "Alice" makes parallel HTTP POST requests to "https://localhost:4466/v1/keystores/{keystoreID}/keys" to create "AES128GCM,ChaCha20Poly1305,XChaCha20Poly1305,ED25519,HMACSHA256Tag256,NISTP256ECDHKW,X25519ECDHKW,BLS12381G2" keys
    Then  "Alice" gets a response with HTTP status "200 OK" for each request

  Scenario: User exports a public key
    Given "Bob" has created a keystore with "ED25519" key on Key Server

    When  "Bob" makes an HTTP GET to "https://localhost:4466/v1/keystores/{keystoreID}/keys/{keyID}/export" to export public key
    Then  "Bob" gets a response with HTTP status "200 OK"
     And  "Bob" gets a response with non-empty "public_key"

  Scenario: User creates and exports a key
    Given "Alice" has created an empty keystore on Key Server

    When  "Alice" makes an HTTP POST to "https://localhost:4466/v1/keystores/{keystoreID}/keys" to create and export "ED25519" key
    Then  "Alice" gets a response with HTTP status "200 OK"
     And  "Alice" gets a response with non-empty "key_url"
     And  "Alice" gets a response with non-empty "public_key"

  Scenario: User imports a private key
    Given "Bob" has created an empty keystore on Key Server

    When  "Bob" makes an HTTP PUT to "https://localhost:4466/v1/keystores/{keystoreID}/keys" to import a private key with ID "keyID"
    Then  "Bob" gets a response with HTTP status "200 OK"
     And  "Bob" gets a response with "key_url" with value "https://kms.trustbloc.local:8076/v1/keystores/([^/]+)/keys/keyID"

  Scenario: User signs a message and verifies a signature
    Given "Alice" has created a keystore with "ED25519" key on Key Server

    When  "Alice" makes an HTTP POST to "https://localhost:4466/v1/keystores/{keystoreID}/keys/{keyID}/sign" to sign "test message"
    Then  "Alice" gets a response with HTTP status "200 OK"
     And  "Alice" gets a response with non-empty "signature"

    When  "Alice" makes an HTTP POST to "https://localhost:4466/v1/keystores/{keystoreID}/keys/{keyID}/verify" to verify "signature" for "test message"
    Then  "Alice" gets a response with HTTP status "200 OK"
     And  "Alice" gets a response with no "errMessage"

  Scenario: User creates and rotates a key
    Given "Alice" has created a keystore with "AES256GCM" key on Key Server
      And "Alice" makes an HTTP POST to "https://localhost:4466/v1/keystores/{keystoreID}/keys/{keyID}/encrypt" to encrypt "test message"

    When  "Alice" makes an HTTP POST to "https://localhost:4466/v1/keystores/{keystoreID}/keys/{keyID}/rotate" to rotate "AES256GCM" key
    Then  "Alice" gets a response with HTTP status "200 OK"

    When  "Alice" makes an HTTP POST to "https://localhost:4466/v1/keystores/{keystoreID}/keys/{keyID}/decrypt" to decrypt "ciphertext"
    Then  "Alice" gets a response with HTTP status "200 OK"
     And  "Alice" gets a response with "plaintext" with value "test message"

  Scenario: User encrypts/decrypts a message
    Given "Bob" has created a keystore with "AES256GCM" key on Key Server

    When  "Bob" makes an HTTP POST to "https://localhost:4466/v1/keystores/{keystoreID}/keys/{keyID}/encrypt" to encrypt "test message"
    Then  "Bob" gets a response with HTTP status "200 OK"
     And  "Bob" gets a response with non-empty "ciphertext"
     And  "Bob" gets a response with non-empty "nonce"

    When  "Bob" makes an HTTP POST to "https://localhost:4466/v1/keystores/{keystoreID}/keys/{keyID}/decrypt" to decrypt "ciphertext"
    Then  "Bob" gets a response with HTTP status "200 OK"
     And  "Bob" gets a response with "plaintext" with value "test message"

  Scenario: User computes/verifies MAC for data
    Given "Alice" has created a keystore with "HMACSHA256Tag256" key on Key Server

    When  "Alice" makes an HTTP POST to "https://localhost:4466/v1/keystores/{keystoreID}/keys/{keyID}/computemac" to compute MAC for "test data"
    Then  "Alice" gets a response with HTTP status "200 OK"
     And  "Alice" gets a response with non-empty "mac"

    When  "Alice" makes an HTTP POST to "https://localhost:4466/v1/keystores/{keystoreID}/keys/{keyID}/verifymac" to verify MAC "mac" for "test data"
    Then  "Alice" gets a response with HTTP status "200 OK"
     And  "Alice" gets a response with no "errMessage"

  Scenario: User A wraps A256GCM key for User B, User B successfully unwraps it (Anoncrypt)
    Given "Alice" has created a keystore with "NISTP256ECDHKW" key on Key Server
      And "Bob" has created a keystore with "NISTP256ECDHKW" key on Key Server
      And "Alice" has a public key of "Bob"

    When  "Alice" makes an HTTP POST to "https://localhost:4466/v1/keystores/{keystoreID}/wrap" to wrap "testCEK" for "Bob"
    Then  "Alice" gets a response with HTTP status "200 OK"
     And  "Alice" gets a response with non-empty "wrapped_key"

    When  "Bob" makes an HTTP POST to "https://localhost:4466/v1/keystores/{keystoreID}/keys/{keyID}/unwrap" to unwrap "wrapped_key" from "Alice"
    Then  "Bob" gets a response with HTTP status "200 OK"
     And  "Bob" gets a response with content of "testCEK" key

  Scenario: User A wraps XC20P key for User B, User B successfully unwraps it (Anoncrypt)
    Given "Alice" has created a keystore with "X25519ECDHKW" key on Key Server
      And "Bob" has created a keystore with "X25519ECDHKW" key on Key Server
      And "Alice" has a public key of "Bob"

    When  "Alice" makes an HTTP POST to "https://localhost:4466/v1/keystores/{keystoreID}/wrap" to wrap "testCEK" for "Bob"
    Then  "Alice" gets a response with HTTP status "200 OK"
     And  "Alice" gets a response with non-empty "wrapped_key"

    When  "Bob" makes an HTTP POST to "https://localhost:4466/v1/keystores/{keystoreID}/keys/{keyID}/unwrap" to unwrap "wrapped_key" from "Alice"
    Then  "Bob" gets a response with HTTP status "200 OK"
     And  "Bob" gets a response with content of "testCEK" key
