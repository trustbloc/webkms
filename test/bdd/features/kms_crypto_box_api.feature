#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@kms_crypto_box
Feature: KMS CryptoBox operations
  Background:
    Given Key Server is running on "localhost" port "4466"
      And AuthZ Key Server is running on "localhost" port "4455"
      And Hub Auth is running on "localhost" port "8070"
      And EDV is running on "localhost" port "8081"
      And "Alice" wallet has stored secret on Hub Auth
      And "Bob" wallet has stored secret on Hub Auth
      And "Alice" has created a data vault on EDV for storing keys
      And "Bob" has created a data vault on EDV for storing keys

  Scenario: User A anonymously encrypts ("easy") a payload for User B, User B decrypts ("easy open") it
    Given "Alice" has created a keystore with "ED25519" key on Key Server
      And "Bob" has created a keystore with "ED25519" key on Key Server
      And "Alice" has a public key of "Bob"
      And "Bob" has a public key of "Alice"

    When  "Alice" makes an HTTP POST to "https://localhost:4466/v1/keystore/{keystoreID}/key/{keyID}/easy" to easy "test payload" for "Bob"
    Then  "Alice" gets a response with HTTP status "200 OK"
     And  "Alice" gets a response with non-empty "ciphertext"

    When  "Bob" makes an HTTP POST to "https://localhost:4466/v1/keystore/{keystoreID}/easyopen" to easyOpen "ciphertext" from "Alice"
    Then  "Bob" gets a response with HTTP status "200 OK"
     And  "Bob" gets a response with "plaintext" with value "test payload"

  Scenario: User B decrypts ("seal open") a payload that was encrypted ("seal") by User A
    Given "Bob" has created a keystore with "ED25519" key on Key Server
      And "Alice" has created a keystore with "ED25519" key on Key Server
      And "Bob" has a public key of "Alice"
      And "Bob" has sealed "test payload" for "Alice"

    When  "Alice" makes an HTTP POST to "https://localhost:4466/v1/keystore/{keystoreID}/sealopen" to sealOpen "ciphertext" from "Bob"
    Then  "Alice" gets a response with HTTP status "200 OK"
     And  "Alice" gets a response with "plaintext" with value "test payload"
