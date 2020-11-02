#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
set -e

echo "Running $0"

GO_TEST_CMD="go test"

go generate ./...
ROOT=$(pwd)
touch "$ROOT"/coverage.out

amend_coverage_file () {
if [ -f profile.out ]; then
     cat profile.out >> "$ROOT"/coverage.out
     rm profile.out
fi
}

# Running hub-kms unit tests
PKGS=$(go list github.com/trustbloc/hub-kms/... 2> /dev/null | grep -v /mocks)
$GO_TEST_CMD $PKGS -count=1 -race -coverprofile=profile.out -covermode=atomic -timeout=10m
amend_coverage_file

# Running kms-rest unit tests
cd cmd/kms-rest
PKGS=$(go list github.com/trustbloc/hub-kms/cmd/kms-rest/... 2> /dev/null | grep -v /mocks)
$GO_TEST_CMD $PKGS -count=1 -race -coverprofile=profile.out -covermode=atomic -timeout=10m
amend_coverage_file
cd "$ROOT" || exit
