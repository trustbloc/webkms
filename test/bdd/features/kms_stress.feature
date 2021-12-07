#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@kms_stress
Feature: KMS stress test
  Background:
    Given Key Server is running on "localhost" port "4466"
      And AuthZ Key Server is running on "localhost" port "4455"
      And Hub Auth is running on "localhost" port "8070"
      And EDV is running on "localhost" port "8081"
      And "USER_NUMS" users wallets has stored secret on Hub Auth
      And "USER_NUMS" users has created a data vault on EDV for storing keys


  Scenario: Stress test sign and verify methods
    Given "USER_NUMS" users has created a keystore with "ED25519" key using "KMS_STRESS_CONCURRENT_REQ" concurrent requests
    When  "USER_NUMS" users makes an HTTP POST to "https://localhost:4466/v1/keystores/{keystoreID}/keys/{keyID}" to sign and verify "KMS_STRESS_TIMES" times using "KMS_STRESS_CONCURRENT_REQ" concurrent requests


