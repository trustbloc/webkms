// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/kms/cmd/kms-rest

go 1.16

require (
	github.com/gorilla/mux v1.8.0
	github.com/hyperledger/aries-framework-go v0.1.7-0.20210811135743-532e65035d3b
	github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb v0.0.0-20210714131038-41b5bccef1f9
	github.com/hyperledger/aries-framework-go-ext/component/vdr/orb v0.0.0-20210813123233-e22ddceee0b1
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210807121559-b41545a4f1e8
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210807121559-b41545a4f1e8
	github.com/piprate/json-gold v0.4.0
	github.com/rs/cors v1.7.0
	github.com/spf13/cobra v1.1.3
	github.com/stretchr/testify v1.7.0
	github.com/trustbloc/edge-core v0.1.7-0.20210812092729-6c61997fa9dd
	github.com/trustbloc/kms v0.0.0-00010101000000-000000000000
	go.opentelemetry.io/otel v0.16.0
	go.opentelemetry.io/otel/exporters/trace/jaeger v0.16.0
	go.opentelemetry.io/otel/sdk v0.16.0
)

replace github.com/trustbloc/kms => ../..
