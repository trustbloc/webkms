// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/hub-kms/cmd/kms-rest

go 1.15

require (
	github.com/gorilla/mux v1.8.0
	github.com/hyperledger/aries-framework-go v0.1.6-0.20201223142031-ac4ce368a9c8
	github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb v0.0.0-20201210203117-e17b615af85d
	github.com/piprate/json-gold v0.3.1-0.20201222165305-f4ce31c02ca3
	github.com/rs/cors v1.7.0
	github.com/spf13/cobra v1.1.1
	github.com/stretchr/testify v1.6.1
	github.com/trustbloc/edge-core v0.1.5
	github.com/trustbloc/hub-kms v0.0.0-00010101000000-000000000000
	go.opentelemetry.io/otel v0.15.0
	go.opentelemetry.io/otel/exporters/trace/jaeger v0.15.0
	go.opentelemetry.io/otel/sdk v0.15.0
	golang.org/x/net v0.0.0-20201224014010-6772e930b67b // indirect
	golang.org/x/sync v0.0.0-20201207232520-09787c993a3a // indirect
	google.golang.org/api v0.36.0 // indirect
)

replace github.com/trustbloc/hub-kms => ../..
