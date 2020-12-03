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

  Scenario: Easy/EasyOpen
    Given "Alice" has created a keystore with "ED25519" key on Key Server
      And "Bob" has created a keystore with "ED25519" key on Key Server
      And "Alice" has a public key of "Bob"
      And "Bob" has a public key of "Alice"

    When  "Alice" makes an HTTP POST to "https://localhost:4466/kms/keystores/{keystoreID}/keys/{keyID}/easy" to easy "test payload" for "Bob"
    Then  "Alice" gets a response with HTTP status "200 OK"
     And  "Alice" gets a response with non-empty "cipherText"

    When  "Bob" makes an HTTP POST to "https://localhost:4466/kms/keystores/{keystoreID}/easyopen" to easyOpen "cipherText" from "Alice"
    Then  "Bob" gets a response with HTTP status "200 OK"
     And  "Bob" gets a response with "plainText" with value "test payload"
