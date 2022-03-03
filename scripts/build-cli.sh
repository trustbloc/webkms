#!/bin/sh
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

set -e



cd /opt/workspace/kms

echo "Building kms cli binaries"

cd cmd/kms-cli/;CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o ../../.build/dist/bin/kms-cli-linux-amd64 main.go
cd /opt/workspace/kms
cd .build/dist/bin;tar cvzf kms-cli-linux-amd64.tar.gz kms-cli-linux-amd64;rm -rf kms-cli-linux-amd64
cd /opt/workspace/kms


cd cmd/kms-cli/;CC=aarch64-linux-gnu-gcc CGO_ENABLED=1 GOOS=linux GOARCH=arm64 go build -o ../../.build/dist/bin/kms-cli-linux-arm64 main.go
cd /opt/workspace/kms
cd .build/dist/bin;tar cvzf kms-cli-linux-arm64.tar.gz kms-cli-linux-arm64;rm -rf kms-cli-linux-arm64
cd /opt/workspace/kms


cd cmd/kms-cli/;CC=aarch64-apple-darwin20.2-clang CXX=aarch64-apple-darwin20.2-clang++ CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build -o ../../.build/dist/bin/kms-cli-darwin-arm64 main.go
cd /opt/workspace/kms
cd .build/dist/bin;tar cvzf kms-cli-darwin-arm64.tar.gz kms-cli-darwin-arm64;rm -rf kms-cli-darwin-arm64
cd /opt/workspace/kms

cd cmd/kms-cli/;CC=o64-clang CXX=o64-clang++ CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build -o ../../.build/dist/bin/kms-cli-darwin-amd64 main.go
cd /opt/workspace/kms
cd .build/dist/bin;tar cvzf kms-cli-darwin-amd64.tar.gz kms-cli-darwin-amd64;rm -rf kms-cli-darwin-amd64
cd /opt/workspace/kms
