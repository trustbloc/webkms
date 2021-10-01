// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/kms/test/bdd

go 1.16

require (
	github.com/cucumber/godog v0.10.0
	github.com/hyperledger/aries-framework-go v0.1.7
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210913152107-80cff90741e9
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210913152107-80cff90741e9
	github.com/igor-pavlenko/httpsignatures-go v0.0.23
	github.com/rs/xid v1.2.1
	github.com/teserakt-io/golang-ed25519 v0.0.0-20210104091850-3888c087a4c8
	github.com/trustbloc/edge-core v0.1.7
	github.com/trustbloc/edv v0.1.7-0.20210907184357-1b74dc1fcea6
	github.com/trustbloc/hub-auth/test/bdd v0.0.0-20210915103052-783e28d5632c
	github.com/trustbloc/kms v0.0.0-00010101000000-000000000000
)

replace (
	github.com/trustbloc/hub-auth => github.com/trustbloc/hub-auth v0.1.7
	github.com/trustbloc/kms => ../..
	// https://github.com/ory/dockertest/issues/208#issuecomment-686820414
	golang.org/x/sys => golang.org/x/sys v0.0.0-20200826173525-f9321e4c35a6
)
