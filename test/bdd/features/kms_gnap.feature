#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@gnap
@wip
Feature: KMS authorization with GNAP
  Scenario: User authorizes with GNAP to create a key store
    Given "Alice" has been granted with GNAP access token to Key Server
    When  an HTTP POST with GNAP access token and "(request-target),authorization,digest" headers signed by "Alice" is sent to "https://localhost:4466/v1/keystores"
          """
          {
            "controller": "{{ .GetDID "Alice" }}"
          }
          """
    Then  response status is "200 OK"
     And  response contains non-empty "key_store_url"
