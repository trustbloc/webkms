#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
set -e

echo "Running $0"

go generate ./...
pwd=`pwd`
echo "" > "$pwd"/coverage.txt

amend_coverage_file () {
if [ -f profile.out ]; then
     cat profile.out >> "$pwd"/coverage.txt
     rm profile.out
fi
}

# Running hub-kms unit tests
PKGS=`go list github.com/trustbloc/hub-kms/... 2> /dev/null | \
                                                  grep -v /mocks`
go test $PKGS -count=1 -race -coverprofile=profile.out -covermode=atomic -timeout=10m
amend_coverage_file

# Running kms-rest unit tests
cd cmd/kms-rest
PKGS=`go list github.com/trustbloc/hub-kms/cmd/kms-rest/... 2> /dev/null | \
                                                 grep -v /mocks`
go test $PKGS -count=1 -race -coverprofile=profile.out -covermode=atomic -timeout=10m
amend_coverage_file
cd "$pwd"
