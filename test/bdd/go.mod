// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/hub-kms/test/bdd

go 1.15

require (
	github.com/cucumber/godog v0.10.0
	github.com/fsouza/go-dockerclient v1.6.6
	github.com/hyperledger/aries-framework-go v0.1.5-0.20201127225407-a71550e3ea9f
	github.com/igor-pavlenko/httpsignatures-go v0.0.21
	github.com/rs/xid v1.2.1
	github.com/trustbloc/edge-core v0.1.5-0.20201126210935-53388acb41fc
	github.com/trustbloc/edv v0.1.5-0.20201126214711-ef96fd4b68b5
	github.com/trustbloc/hub-auth v0.0.0-20201124144255-48d4c6f991b8 // indirect
	github.com/trustbloc/hub-auth/test/bdd v0.0.0-20201124144255-48d4c6f991b8
	github.com/trustbloc/hub-kms v0.0.0-00010101000000-000000000000
)

replace (
	github.com/kilic/bls12-381 => github.com/trustbloc/bls12-381 v0.0.0-20201104214312-31de2a204df8
	github.com/trustbloc/hub-kms => ../..
	// https://github.com/ory/dockertest/issues/208#issuecomment-686820414
	golang.org/x/sys => golang.org/x/sys v0.0.0-20200826173525-f9321e4c35a6
)
