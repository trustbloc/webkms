# Copyright SecureKey Technologies Inc.
#
# SPDX-License-Identifier: Apache-2.0

KMS_REST_PATH=cmd/kms-rest

# Namespace for the agent images
DOCKER_OUTPUT_NS   ?= docker.pkg.github.com
KMS_REST_IMAGE_NAME   ?= trustbloc/hub-kms/kms-rest

# Tool commands (overridable)
ALPINE_VER ?= 3.11
GO_VER ?= 1.14

.PHONY: all
all: checks unit-test

.PHONY: checks
checks: license lint

.PHONY: lint
lint:
	@scripts/check_lint.sh

.PHONY: license
license:
	@scripts/check_license.sh

.PHONY: unit-test
unit-test:
	@scripts/check_unit.sh

.PHONY: kms-rest
kms-rest:
	@echo "Building kms-rest"
	@mkdir -p ./.build/bin
	@cd ${KMS_REST_PATH} && go build -o ../../.build/bin/kms-rest main.go

.PHONY: kms-rest-docker
kms-rest-docker:
	@echo "Building kms rest docker image"
	@docker build -f ./images/kms-rest/Dockerfile --no-cache -t $(DOCKER_OUTPUT_NS)/$(KMS_REST_IMAGE_NAME):latest \
	--build-arg GO_VER=$(GO_VER) \
	--build-arg ALPINE_VER=$(ALPINE_VER) .

.PHONY: clean
clean: clean-build

.PHONY: clean-build
clean-build:
	@rm -Rf ./.build
