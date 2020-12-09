// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/hub-kms

go 1.15

require (
	github.com/bluele/gcache v0.0.0-20190518031135-bc40bd653833
	github.com/google/tink/go v1.5.0
	github.com/google/uuid v1.1.2
	github.com/gorilla/mux v1.8.0
	github.com/hyperledger/aries-framework-go v0.1.5
	github.com/igor-pavlenko/httpsignatures-go v0.0.21
	github.com/piprate/json-gold v0.3.0
	github.com/rs/xid v1.2.1
	github.com/stretchr/testify v1.6.1
	github.com/trustbloc/edge-core v0.1.5
)

replace github.com/kilic/bls12-381 => github.com/trustbloc/bls12-381 v0.0.0-20201104214312-31de2a204df8
