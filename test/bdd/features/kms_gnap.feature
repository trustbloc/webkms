#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@gnap
Feature: KMS authorization with GNAP
  Scenario: User authorizes with GNAP for KMS operations
    Given "Alice" has been granted with GNAP access token to Key Server
    # create a key store
    When  an HTTP POST with GNAP access token and "(request-target),authorization,digest" headers signed by "Alice" is sent to "https://localhost:8076/v1/keystores"
          """
          {
            "controller": "{{ .GetDID "Alice" }}"
          }
          """
    Then  response status is "200 OK"
     And  response contains non-empty "key_store_url"
    # create a key
    When  an HTTP POST with GNAP access token and "(request-target),authorization,digest" headers signed by "Alice" is sent to "https://localhost:8076/v1/keystores/{keystoreID}/keys"
          """
          {
            "key_type": "ED25519"
          }
          """
    Then  response status is "200 OK"
     And  response contains non-empty "key_url"
    # sign a message
    When  an HTTP POST with GNAP access token and "(request-target),authorization,digest" headers signed by "Alice" is sent to "https://localhost:8076/v1/keystores/{keystoreID}/keys/{keyID}/sign"
          """
          {
            "message": "{{ .ToBase64 "test message" }}"
          }
          """
    Then  response status is "200 OK"
     And  response contains non-empty "signature"

