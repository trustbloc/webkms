// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/kms/test/bdd

go 1.16

require (
	github.com/cucumber/godog v0.10.0
	github.com/fsouza/go-dockerclient v1.6.6
	github.com/hyperledger/aries-framework-go v0.1.7-0.20210429205242-c5e97865879c
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210429205242-c5e97865879c
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210429205242-c5e97865879c
	github.com/igor-pavlenko/httpsignatures-go v0.0.23
	github.com/rs/xid v1.2.1
	github.com/teserakt-io/golang-ed25519 v0.0.0-20210104091850-3888c087a4c8
	github.com/trustbloc/edge-core v0.1.7-0.20210429222332-96b987820e63
	github.com/trustbloc/edv v0.1.7-0.20210430161950-53b68c73153c
	github.com/trustbloc/hub-auth/test/bdd v0.0.0-20210430144505-5dd263e274da
	github.com/trustbloc/kms v0.0.0-00010101000000-000000000000
)

replace (
	github.com/trustbloc/kms => ../..
	// https://github.com/ory/dockertest/issues/208#issuecomment-686820414
	golang.org/x/sys => golang.org/x/sys v0.0.0-20200826173525-f9321e4c35a6
)
