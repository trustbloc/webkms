// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/kms/cmd/kms-rest

go 1.15

require (
	github.com/cenkalti/backoff/v3 v3.2.2 // indirect
	github.com/containerd/continuity v0.0.0-20200928162600-f2cc35102c2a // indirect
	github.com/gorilla/mux v1.8.0
	github.com/hyperledger/aries-framework-go v0.1.6-0.20210225161605-5a3ea609e830
	github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb v0.0.0-20210227073053-5d4fd6ad6b43
	github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc v0.0.0-20210209170459-14c492334960
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210225210554-4f581697f7ec
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210301145929-dc1a9b33494a
	github.com/rs/cors v1.7.0
	github.com/sirupsen/logrus v1.7.0 // indirect
	github.com/spf13/cobra v1.1.2
	github.com/stretchr/testify v1.7.0
	github.com/trustbloc/edge-core v0.1.6-0.20210224175343-275d0e0370c4
	github.com/trustbloc/kms v0.0.0-00010101000000-000000000000
	go.opentelemetry.io/otel v0.16.0
	go.opentelemetry.io/otel/exporters/trace/jaeger v0.16.0
	go.opentelemetry.io/otel/sdk v0.16.0
	golang.org/x/net v0.0.0-20210226172049-e18ecbb05110 // indirect
	golang.org/x/sync v0.0.0-20201207232520-09787c993a3a // indirect
)

replace github.com/trustbloc/kms => ../..
