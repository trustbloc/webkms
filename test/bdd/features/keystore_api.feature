#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@keystore
Feature: Keystore management operations

  Scenario: User creates a keystore
    Given Key Server is running on "localhost" port "4466"
    When  user makes an HTTP POST to "https://localhost:4466/v1/keystores" to create a keystore
    Then  user gets a response with HTTP status "200 OK" and valid key store URL and root capabilities
