#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@keystore
Feature: Keystore management operations

  Scenario: User creates a keystore
    Given Key Server is running on "localhost" port "8076"
    When  user makes an HTTP POST to "https://localhost:8076/kms/keystores" to create a keystore
    Then  user gets a response with HTTP status "201 Created" and with valid "Location" and "X-RootCapability" headers
