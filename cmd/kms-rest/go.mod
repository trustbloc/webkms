// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/hub-kms/cmd/kms-rest

go 1.15

require (
	github.com/gorilla/mux v1.8.0
	github.com/hyperledger/aries-framework-go v0.1.5-0.20201124194436-a37f1c10fd4e
	github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb v0.0.0-20201119153638-fc5d5e680587
	github.com/rs/cors v1.7.0
	github.com/spf13/cobra v1.1.1
	github.com/stretchr/testify v1.6.1
	github.com/trustbloc/edge-core v0.1.5-0.20201126210935-53388acb41fc
	github.com/trustbloc/hub-kms v0.0.0-00010101000000-000000000000
	golang.org/x/net v0.0.0-20201110031124-69a78807bb2b // indirect
)

replace (
	github.com/kilic/bls12-381 => github.com/trustbloc/bls12-381 v0.0.0-20201104214312-31de2a204df8
	github.com/trustbloc/hub-kms => ../..
)
