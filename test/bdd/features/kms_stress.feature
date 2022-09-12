#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@kms_stress
Feature: KMS stress test
  Background:
    Given Key Server is running on "KMS_STRESS_KMS_URL" env

  @kms_stress_local
  Scenario: Stress test KMS methods with local storage
    When  Create "USER_NUMS" users
    And  "USER_NUMS" users request to create a keystore on "LocalStorage" with "ED25519" key and sign 1 times using "KMS_STRESS_CONCURRENT_REQ" concurrent requests

