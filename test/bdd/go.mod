// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/hub-kms/test/bdd

go 1.15

require (
	github.com/cucumber/godog v0.10.0
	github.com/fsouza/go-dockerclient v1.6.6
	github.com/hyperledger/aries-framework-go v0.1.5-0.20201206074507-a97d9e952232
	github.com/igor-pavlenko/httpsignatures-go v0.0.21
	github.com/rs/xid v1.2.1
	github.com/teserakt-io/golang-ed25519 v0.0.0-20200315192543-8255be791ce4
	github.com/trustbloc/edge-core v0.1.5-0.20201204205054-05009dc0285c
	github.com/trustbloc/edv v0.1.5-0.20201205011837-b7da60f23958
	github.com/trustbloc/hub-auth v0.0.0-20201204204840-e904628d7854 // indirect
	github.com/trustbloc/hub-auth/test/bdd v0.0.0-20201204204840-e904628d7854
	github.com/trustbloc/hub-kms v0.0.0-00010101000000-000000000000
)

replace (
	github.com/kilic/bls12-381 => github.com/trustbloc/bls12-381 v0.0.0-20201104214312-31de2a204df8
	github.com/trustbloc/hub-kms => ../..
	// https://github.com/ory/dockertest/issues/208#issuecomment-686820414
	golang.org/x/sys => golang.org/x/sys v0.0.0-20200826173525-f9321e4c35a6
)
