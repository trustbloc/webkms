#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@kms_crypto_box
Feature: KMS CryptoBox operations
  Background:
    Given Key Server is running on "localhost" port "8076"
      And "Alice" has configured ZCAP authentication
      And "Bob" has configured ZCAP authentication

  Scenario: User A anonymously encrypts (wrap as "easy") a payload for User B, User B decrypts (unwrap as "easy open") it
    Given "Alice" has created a keystore with "ED25519" key on Key Server
      And "Bob" has created a keystore with "ED25519" key on Key Server
      And "Alice" has a public key of "Bob"
      And "Bob" has a public key of "Alice"

    When  "Alice" makes an HTTP POST to "https://localhost:8076/v1/keystores/{keystoreID}/keys/{keyID}/wrap" to easy "test payload" for "Bob"
    Then  "Alice" gets a response with HTTP status "200 OK"
     And  "Alice" gets a response with non-empty "ciphertext"

    # since easyOpen now works like unwrap, adding `keys/{keyID}` below is necessary to follow the same pattern as unwrap even if
    # easyOpen does not use keyID (it uses keys found in the POST request instead)
    When  "Bob" makes an HTTP POST to "https://localhost:8076/v1/keystores/{keystoreID}/keys/{keyID}/unwrap" to easyOpen "ciphertext" from "Alice"
    Then  "Bob" gets a response with HTTP status "200 OK"
     And  "Bob" gets a response with "plaintext" with value "test payload"

  Scenario: User B decrypts ("seal open") a payload that was encrypted ("seal") by User A
    Given "Bob" has created a keystore with "ED25519" key on Key Server
      And "Alice" has created a keystore with "ED25519" key on Key Server
      And "Bob" has a public key of "Alice"
      And "Bob" has sealed "test payload" for "Alice"

    # since sealOpen now works like unwrap, adding `keys/{keyID}` below is necessary to follow the same pattern as unwrap even if
    # sealOpen does not use keyID (it uses keys found in the POST request instead)
    When  "Alice" makes an HTTP POST to "https://localhost:8076/v1/keystores/{keystoreID}/keys/{keyID}/unwrap" to sealOpen "ciphertext" from "Bob"
    Then  "Alice" gets a response with HTTP status "200 OK"
     And  "Alice" gets a response with "plaintext" with value "test payload"
