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


  @kms_stress_local
  Scenario: Stress test KMS methods with local storage
    When  "USER_NUMS" users request to "KMS_STRESS_KMS_URL" to create a keystore on "LocalStorage" with "ED25519" key using "KMS_STRESS_CONCURRENT_REQ" concurrent requests

  @kms_stress_edv
  Scenario: Stress test KMS methods with EDV storage
    When  "USER_NUMS" users request to "KMS_STRESS_KMS_URL" to create a keystore on "EDV" with "ED25519" key using "KMS_STRESS_CONCURRENT_REQ" concurrent requests


