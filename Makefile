# Copyright SecureKey Technologies Inc.
#
# SPDX-License-Identifier: Apache-2.0

KMS_REST_PATH=cmd/kms-rest

# Namespace for the agent images
DOCKER_OUTPUT_NS   ?= ghcr.io
KMS_IMAGE_NAME   ?= trustbloc/kms

# OpenAPI spec
OPENAPI_DOCKER_IMG=quay.io/goswagger/swagger
OPENAPI_SPEC_PATH=.build/rest/openapi/spec
OPENAPI_DOCKER_IMG_VERSION=v0.25.0

# Tool commands (overridable)
ALPINE_VER ?= 3.12
GO_VER ?= 1.15

.PHONY: all
all: checks unit-test

.PHONY: checks
checks: license lint generate-openapi-spec

.PHONY: lint
lint:
	@scripts/check_lint.sh

.PHONY: license
license:
	@scripts/check_license.sh

.PHONY: unit-test
unit-test:
	@scripts/check_unit.sh

.PHONY: bdd-test
bdd-test: clean kms-docker generate-test-keys mock-login-consent-docker
	@scripts/check_integration.sh

.PHONY: mock-login-consent-docker
mock-login-consent-docker:
	@echo "Building mock login consent server for BDD tests..."
	@cd test/bdd/mock/loginconsent && docker build -f image/Dockerfile --build-arg GO_VER=$(GO_VER) --build-arg ALPINE_VER=$(ALPINE_VER) -t mockloginconsent:latest .

.PHONY: kms-rest
kms-rest:
	@echo "Building kms-rest"
	@mkdir -p ./.build/bin
	@cd ${KMS_REST_PATH} && go build -o ../../.build/bin/kms-rest main.go

.PHONY: kms-docker
kms-docker:
	@echo "Building kms rest docker image"
	@docker build -f ./images/kms-rest/Dockerfile --no-cache -t $(DOCKER_OUTPUT_NS)/$(KMS_IMAGE_NAME):latest \
	--build-arg GO_VER=$(GO_VER) \
	--build-arg ALPINE_VER=$(ALPINE_VER) .

.PHONY: generate-test-keys
generate-test-keys: clean
	@mkdir -p -p test/bdd/fixtures/keys/tls
	@docker run -i --rm \
		-v $(abspath .):/opt/workspace/kms \
		--entrypoint "/opt/workspace/kms/scripts/generate_test_keys.sh" \
		frapsoft/openssl

.PHONY: generate-openapi-spec
generate-openapi-spec: clean
	@echo "Generating and validating controller API specifications using Open API"
	@mkdir -p .build/rest/openapi/spec
	@SPEC_META=$(VC_REST_PATH) SPEC_LOC=${OPENAPI_SPEC_PATH}  \
	DOCKER_IMAGE=$(OPENAPI_DOCKER_IMG) DOCKER_IMAGE_VERSION=$(OPENAPI_DOCKER_IMG_VERSION)  \
	scripts/generate-openapi-spec.sh

.PHONY: generate-openapi-demo-specs
generate-openapi-demo-specs: clean generate-openapi-spec kms-docker
	@echo "Generate demo KMS rest controller API specifications using Open API"
	@SPEC_PATH=${OPENAPI_SPEC_PATH} OPENAPI_DEMO_PATH=test/bdd/fixtures/openapi-demo \
    	DOCKER_IMAGE=$(OPENAPI_DOCKER_IMG) DOCKER_IMAGE_VERSION=$(OPENAPI_DOCKER_IMG_VERSION)  \
    	scripts/generate-openapi-demo-specs.sh

.PHONY: run-openapi-demo
run-openapi-demo: generate-openapi-demo-specs
	@echo "Starting OpenAPI demo..."
	@FIXTURES_PATH=test/bdd/fixtures  \
        scripts/run-openapi-demo.sh

.PHONY: clean
clean: clean-build

.PHONY: clean-build
clean-build:
	@rm -Rf ./.build
	@rm -Rf ./test/bdd/fixtures/keys/tls
	@rm -Rf ./test/bdd/docker-compose.log
