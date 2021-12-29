#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@kms_stress
Feature: KMS stress test
  Background:
    Given Key Server is running on "KMS_STRESS_KMS_URL" env
      And AuthZ Key Server is running on "KMS_STRESS_AUTH_KMS_URL" env
      And Hub Auth is running on "KMS_STRESS_HUB_AUTH_URL" env
      And EDV is running on "KMS_STRESS_EDV_URL" env
      And "USER_NUMS" users wallets has stored secret on Hub Auth
      And "USER_NUMS" users has created a data vault on EDV for storing keys


  @kms_stress_local
  Scenario: Stress test KMS methods with local storage
    When  "USER_NUMS" users request to create a keystore on "LocalStorage" with "ED25519" key and sign/verify "KMS_STRESS_SIGN_VERIFY_TIMES" times using "KMS_STRESS_CONCURRENT_REQ" concurrent requests

  @kms_stress_edv
  Scenario: Stress test KMS methods with EDV storage
    When  "USER_NUMS" users request to create a keystore on "EDV" with "ED25519" key and sign/verify "KMS_STRESS_SIGN_VERIFY_TIMES" times using "KMS_STRESS_CONCURRENT_REQ" concurrent requests


