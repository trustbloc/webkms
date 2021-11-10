# Copyright SecureKey Technologies Inc.
#
# SPDX-License-Identifier: Apache-2.0

GOBIN_PATH      =$(abspath .)/build/bin
LINT_VERSION    ?=v1.39.0
SWAGGER_VERSION ?=v0.27.0
SWAGGER_DIR     ="./test/bdd/fixtures/specs"
SWAGGER_OUTPUT  =$(SWAGGER_DIR)"/openAPI.yml"

DOCKER_OUTPUT_NS      ?=ghcr.io
KMS_SERVER_IMAGE_NAME ?=trustbloc/kms

ALPINE_VER ?= 3.14
GO_VER     ?= 1.17

OS := $(shell uname)
ifeq  ($(OS),$(filter $(OS),Darwin Linux))
	PATH:=$(PATH):$(GOBIN_PATH)
else
	PATH:=$(PATH);$(subst /,\\,$(GOBIN_PATH))
endif

.PHONY: all
all: clean checks unit-test bdd-test

.PHONY: checks
checks: clean license lint

.PHONY: license
license:
	@scripts/check_license.sh

.PHONY: lint
lint:
	@GOBIN=$(GOBIN_PATH) go install github.com/golangci/golangci-lint/cmd/golangci-lint@$(LINT_VERSION)
	@$(GOBIN_PATH)/golangci-lint run

.PHONY: unit-test
unit-test:
	@go test $(shell go list ./... | grep -v /test/bdd) -count=1 -race -coverprofile=coverage.out -covermode=atomic -timeout=10m

.PHONY: bdd-test
bdd-test: generate-test-keys kms-server-docker
	@cd test/bdd && MallocNanoZone=0 go test -count=1 -v -cover . -p 1 -timeout=10m -race # TODO: remove "MallocNanoZone=0" after resolving https://github.com/golang/go/issues/49138

.PHONY: kms-server
kms-server:
	@echo "Building kms-server"
	@cd cmd/kms-server && go build -o ../../build/bin/kms-server

.PHONY: kms-server-docker
kms-server-docker:
	@echo "Building kms-server docker image"
	@docker build -f ./images/kms-server/Dockerfile --no-cache -t $(DOCKER_OUTPUT_NS)/$(KMS_SERVER_IMAGE_NAME):latest \
	--build-arg GO_VER=$(GO_VER) \
	--build-arg ALPINE_VER=$(ALPINE_VER) .

.PHONY: generate-test-keys
generate-test-keys:
	@mkdir -p ./test/bdd/fixtures/keys/tls
	@docker run -i --rm \
		-v $(abspath .):/opt/workspace/kms \
		--entrypoint "/opt/workspace/kms/scripts/generate_test_keys.sh" \
		frapsoft/openssl

.PHONY: clean
clean:
	@rm -rf ./build
	@rm -rf ./test/bdd/fixtures/kms/keys/tls
	@rm -rf ./test/bdd/build
	@rm -rf coverage.out
	@rm -rf $(SWAGGER_DIR)

.PHONY: open-api-spec
open-api-spec:
	@GOBIN=$(GOBIN_PATH) go install github.com/go-swagger/go-swagger/cmd/swagger@$(SWAGGER_VERSION)
	@echo "Generating Open API spec"
	@mkdir $(SWAGGER_DIR)
	@$(GOBIN_PATH)/swagger generate spec -w ./cmd/kms-server -o $(SWAGGER_OUTPUT)
	@echo "Validating generated spec"
	@$(GOBIN_PATH)/swagger validate $(SWAGGER_OUTPUT)

.PHONY: run-open-api-demo
run-open-api-demo: clean kms-server-docker generate-test-keys open-api-spec
	@echo "Running Open API demo on http://localhost:8089/openapi"
	@docker-compose -f test/bdd/fixtures/openapi-demo/docker-compose.yml up --force-recreate -d kms-server.openapi.com
