#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@kms_cli
Feature: Using kms CLI
  @kms_cli
  Scenario: test create keystore and key using cli
    When KMS keystore is created through cli
    Then check cli created valid keystore
    When KMS key is created through cli
    Then check cli created valid key
