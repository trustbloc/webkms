// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/hub-kms/cmd/kms-rest

go 1.15

require (
	github.com/gorilla/mux v1.8.0
	github.com/hyperledger/aries-framework-go v0.1.4-0.20200827170810-92a1bcd9fd85
	github.com/rs/cors v1.7.0
	github.com/spf13/cobra v1.0.0
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/stretchr/testify v1.6.1
	github.com/trustbloc/edge-core v0.1.4
	github.com/trustbloc/hub-kms v0.0.0-00010101000000-000000000000
)

replace github.com/trustbloc/hub-kms => ../..
