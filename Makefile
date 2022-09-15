# Copyright SecureKey Technologies Inc.
#
# SPDX-License-Identifier: Apache-2.0

GOBIN_PATH      =$(abspath .)/build/bin
LINT_VERSION    ?=v1.44.2
MOCK_VERSION 	?=v1.6.0
SWAGGER_VERSION ?=v0.27.0
SWAGGER_DIR     ="./test/bdd/fixtures/specs"
SWAGGER_OUTPUT  =$(SWAGGER_DIR)"/openAPI.yml"

DOCKER_OUTPUT_NS      ?=ghcr.io
KMS_SERVER_IMAGE_NAME ?=trustbloc/kms

ALPINE_VER ?= 3.14
GO_VER     ?= 1.18

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

.PHONY: mocks
mocks:
	@GOBIN=$(GOBIN_PATH) go install github.com/golang/mock/mockgen@$(MOCK_VERSION)
	@go generate ./...

.PHONY: lint
lint: mocks
	@GOBIN=$(GOBIN_PATH) go install github.com/golangci/golangci-lint/cmd/golangci-lint@$(LINT_VERSION)
	$(GOBIN_PATH)/golangci-lint run -c .golangci.yml

.PHONY: unit-test
unit-test: mocks
	@go test ./... -count=1 -race -coverprofile=coverage.out -covermode=atomic -timeout=10m
	@cd cmd/kms-server && MallocNanoZone=0 go test ./... -count=1 -race -coverprofile=coverage.out -covermode=atomic -timeout=10m

.PHONY: build-kms-cli-binaries
build-kms-cli-binaries:
	@mkdir -p .build/dist/bin
	@docker run -i --rm \
		-v $(abspath .):/opt/workspace/kms \
		--entrypoint "/opt/workspace/kms/scripts/build-cli.sh" \
		ghcr.io/gythialy/golang-cross:latest

.PHONY: extract-kms-cli-binaries
extract-kms-cli-binaries:
	@echo "Extract kms cli binaries"
	@mkdir -p .build/extract;cd .build/dist/bin;tar -zxf kms-cli-linux-amd64.tar.gz;mv kms-cli-linux-amd64 ../../extract/
	@mkdir -p .build/extract;cd .build/dist/bin;tar -zxf kms-cli-darwin-amd64.tar.gz;mv kms-cli-darwin-amd64 ../../extract/

.PHONY: bdd-test
bdd-test: generate-test-keys kms-server-docker mock-login-consent-docker build-kms-cli-binaries extract-kms-cli-binaries
	@cd test/bdd && MallocNanoZone=0 go test -count=1 -v -cover . -p 1 -timeout=10m -race # TODO: remove "MallocNanoZone=0" after resolving https://github.com/golang/go/issues/49138

.PHONY: stress-test
stress-test:
	@cd test/bdd && \
	KMS_STRESS_KMS_URL=https://ops-oathkeeper-proxy.dev.trustbloc.dev \
	KMS_STRESS_AUTH_KMS_URL=https://authz-oathkeeper-proxy.dev.trustbloc.dev \
	KMS_STRESS_HUB_AUTH_URL=https://hub-auth.dev.trustbloc.dev \
	SUBJECT=john.smith23140954@example.com \
	ACCESS_TOKEN=m_QNKTLWFgyFEGPf6dHHs3h3f0TOoJ2ZSlD912u_LKw.6xWwAF61vGM5EHxGuQG9nuwAwd_hNKqMMEe4W2V-V1Q \
	SECRET_SHARE=dD78WKu9/51CRFVhmzlH7nUYbaZvC5Eb30WNC3rfPjLz \
	USER_NUMS=1 \
	DISABLE_COMPOSITION=true \
	DISABLE_CUSTOM_CA=true \
	KMS_STRESS_CONCURRENT_REQ=1 \
	MallocNanoZone=0 TAGS=kms_stress_ops \
	go test -count=1 -v -cover . -p 1 -timeout=10m -race # TODO: remove "MallocNanoZone=0" after resolving https://github.com/golang/go/issues/49138

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

.PHONY: mock-login-consent-docker
mock-login-consent-docker:
	@echo "Building mock login consent server"
	@cd test/bdd/mock/loginconsent && docker build -f image/Dockerfile --build-arg GO_VER=$(GO_VER) --build-arg ALPINE_VER=$(ALPINE_VER) -t mockloginconsent:latest .

# TODO (#334): frapsoft/openssl only has an amd64 version. While this does work under amd64 and arm64 Mac OS currently,
#               we should add an arm64 version for systems that can only run arm64 code.
.PHONY: generate-test-keys
generate-test-keys:
	@mkdir -p ./test/bdd/fixtures/keys/tls
	@docker run -i  --platform linux/amd64 --rm \
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
	@find . -name "gomocks_test.go" -delete

.PHONY: open-api-spec
open-api-spec:
	@GOBIN=$(GOBIN_PATH) go install github.com/go-swagger/go-swagger/cmd/swagger@$(SWAGGER_VERSION)
	@echo "Generating Open API spec"
	@mkdir $(SWAGGER_DIR)
	@$(GOBIN_PATH)/swagger generate spec -w ./cmd/kms-server -x github.com/trustbloc/orb -o $(SWAGGER_OUTPUT)
	@echo "Validating generated spec"
	@$(GOBIN_PATH)/swagger validate $(SWAGGER_OUTPUT)

.PHONY: open-api-demo
open-api-demo: clean kms-server-docker generate-test-keys open-api-spec
	@echo "Running Open API demo on http://localhost:8089/openapi"
	@docker-compose -f test/bdd/fixtures/docker-compose.yml up --force-recreate -d kms-server.openapi.com
