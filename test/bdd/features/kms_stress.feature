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
     And  "USER_NUMS" users request to create a keystore on "LocalStorage" with "ED25519" key and sign/verify using "KMS_STRESS_CONCURRENT_REQ" concurrent requests

  @kms_stress_authz
  Scenario: Stress test KMS methods with EDV storage
    When AuthZ Key Server is running on "KMS_STRESS_AUTH_KMS_URL" env
     And Hub Auth is running on "KMS_STRESS_HUB_AUTH_URL" env
     And "John" login with "SUBJECT" and gets "ACCESS_TOKEN" and "SECRET_SHARE" env
     And "USER_NUMS" requests to authz kms to create a keystore and a key for user "John" and sign using "KMS_STRESS_CONCURRENT_REQ" concurrent requests


