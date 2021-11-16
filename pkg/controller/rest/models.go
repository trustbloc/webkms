/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rest

import (
	"time"

	"github.com/trustbloc/kms/pkg/controller/command"
)

// createDIDReq model
//
// swagger:parameters createDIDReq
type createDIDReq struct{} //nolint:unused,deadcode

// createDIDResp model
//
// swagger:response createDIDResp
type createDIDResp struct { //nolint:unused,deadcode
	// in: body
	Body struct {
		DID string `json:"did"`
	}
}

// createKeyStoreReq model
//
// swagger:parameters createKeyStoreReq
type createKeyStoreReq struct { //nolint:unused,deadcode
	// The header with a user (subject) to use for fetching secret share from Auth server.
	//
	// Auth-User header
	AuthUser string `json:"Auth-User"`

	// The header with a secret share for Shamir secret lock.
	//
	// Secret-Share header
	SecretShare string `json:"Secret-Share"`

	// in: body
	Body command.CreateKeyStoreRequest
}

// createKeyStoreResp model
//
// swagger:response createKeyStoreResp
type createKeyStoreResp struct { //nolint:unused,deadcode
	// in: body
	Body command.CreateKeyStoreResponse
}

// createKeyReq model
//
// swagger:parameters createKeyReq
type createKeyReq struct { //nolint:unused,deadcode
	// The key store's ID.
	//
	// in: path
	// required: true
	KeyStoreID string `json:"key_store_id"`

	// in: body
	Body command.CreateKeyRequest
}

// createKeyResp model
//
// swagger:response createKeyResp
type createKeyResp struct { //nolint:unused,deadcode
	// in: body
	Body command.CreateKeyResponse
}

// importKeyReq model
//
// swagger:parameters importKeyReq
type importKeyReq struct { //nolint:unused,deadcode
	// The key store's ID.
	//
	// in: path
	// required: true
	KeyStoreID string `json:"key_store_id"`

	// in: body
	Body command.ImportKeyRequest
}

// importKeyResp model
//
// swagger:response importKeyResp
type importKeyResp struct { //nolint:unused,deadcode
	// in: body
	Body command.ImportKeyResponse
}

// exportKeyReq model
//
// swagger:parameters exportKeyReq
type exportKeyReq struct { //nolint:unused,deadcode
	// The key store's ID
	//
	// in: path
	// required: true
	KeyStoreID string `json:"key_store_id"`

	// The key's ID
	//
	// in: path
	// required: true
	KeyID string `json:"key_id"`
}

// exportKeyResp model
//
// swagger:response exportKeyResp
type exportKeyResp struct { //nolint:unused,deadcode
	// in: body
	Body command.ExportKeyResponse
}

// signReq model
//
// swagger:parameters signReq
type signReq struct { //nolint:unused,deadcode
	// The key store's ID
	//
	// in: path
	// required: true
	KeyStoreID string `json:"key_store_id"`

	// The key's ID
	//
	// in: path
	// required: true
	KeyID string `json:"key_id"`

	// in: body
	Body command.SignRequest
}

// signResp model
//
// swagger:response signResp
type signResp struct { //nolint:unused,deadcode
	// in: body
	Body command.SignResponse
}

// verifyReq model
//
// swagger:parameters verifyReq
type verifyReq struct { //nolint:unused,deadcode
	// The key store's ID
	//
	// in: path
	// required: true
	KeyStoreID string `json:"key_store_id"`

	// The key's ID
	//
	// in: path
	// required: true
	KeyID string `json:"key_id"`

	// in: body
	Body command.VerifyRequest
}

// verifyResp model
//
// swagger:response verifyResp
type verifyResp struct{} //nolint:unused,deadcode

// encryptReq model
//
// swagger:parameters encryptReq
type encryptReq struct { //nolint:unused,deadcode
	// The key store's ID
	//
	// in: path
	// required: true
	KeyStoreID string `json:"key_store_id"`

	// The key's ID
	//
	// in: path
	// required: true
	KeyID string `json:"key_id"`

	// in: body
	Body command.EncryptRequest
}

// encryptResp model
//
// swagger:response encryptResp
type encryptResp struct { //nolint:unused,deadcode
	// in: body
	Body command.EncryptResponse
}

// decryptReq model
//
// swagger:parameters decryptReq
type decryptReq struct { //nolint:unused,deadcode
	// The key store's ID
	//
	// in: path
	// required: true
	KeyStoreID string `json:"key_store_id"`

	// The key's ID
	//
	// in: path
	// required: true
	KeyID string `json:"key_id"`

	// in: body
	Body command.DecryptRequest
}

// decryptResp model
//
// swagger:response decryptResp
type decryptResp struct { //nolint:unused,deadcode
	// in: body
	Body command.DecryptResponse
}

// healthCheckReq model
//
// swagger:parameters healthCheckRequest
type healthCheckReq struct{} //nolint:unused,deadcode

// healthCheckResp model
//
// swagger:response healthCheckResp
type healthCheckResp struct { //nolint:unused,deadcode
	// in: body
	Body struct {
		Status      string    `json:"status"`
		CurrentTime time.Time `json:"current_time"`
	}
}

// errorResp model
//
// swagger:response errorResp
type errorResp struct { //nolint:unused,deadcode
	// The error message
	//
	// in: body
	Body ErrorResponse
}
