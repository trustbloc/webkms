#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@healthcheck
Feature: health check

  Scenario:
    When HTTP GET is sent to "http://localhost:8070/healthcheck"
    Then The "status" field in the response has the value "success"
