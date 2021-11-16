/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rest

import (
	"time"
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
	Body struct {
		// Controller of the key store.
		// required: true
		Controller string `json:"controller"`

		// Options for EDV-backed key store. If empty, key store is created in server's storage.
		EDV struct {
			// Vault URL on EDV server.
			VaultURL string `json:"vault_url"`

			// Base64-encoded EDV ZCAPs.
			Capability string `json:"capability"`
		} `json:"edv"`
	}
}

// createKeyStoreResp model
//
// swagger:response createKeyStoreResp
type createKeyStoreResp struct { //nolint:unused,deadcode
	// in: body
	Body struct {
		// Key store URL.
		KeyStoreURL string `json:"key_store_url"`

		// Base64-encoded root ZCAPs for key store.
		Capability string `json:"capability"`
	}
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
	Body struct {
		// A type of key to create. Check https://github.com/hyperledger/aries-framework-go/blob/main/pkg/kms/api.go
		// for supported key types.
		KeyType string `json:"key_type"`
	}
}

// createKeyResp model
//
// swagger:response createKeyResp
type createKeyResp struct { //nolint:unused,deadcode
	// in: body
	Body struct {
		// URL to created key.
		KeyURL string `json:"key_url"`

		// A base64-encoded public key. It is empty if key is symmetric.
		PublicKey string `json:"public_key"`
	}
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
	Body struct {
		// A base64-encoded key to import.
		// required: true
		Key string `json:"key"`

		// A type of key to be imported.
		// required: true
		KeyType string `json:"key_type"`

		// An optional key ID to associate imported key with.
		KeyID string `json:"key_id,omitempty"`
	}
}

// importKeyResp model
//
// swagger:response importKeyResp
type importKeyResp struct { //nolint:unused,deadcode
	// in: body
	Body struct {
		// URL of imported key.
		KeyURL string `json:"key_url"`
	}
}

// exportKeyReq model
//
// swagger:parameters exportKeyReq
type exportKeyReq struct { //nolint:unused,deadcode
	// The key store's ID.
	//
	// in: path
	// required: true
	KeyStoreID string `json:"key_store_id"`

	// The key's ID.
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
	Body struct {
		// A base64-encoded public key.
		PublicKey string `json:"public_key"`
	}
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
	Body struct {
		// A base64-encoded message to sign.
		Message string `json:"message"`
	}
}

// signResp model
//
// swagger:response signResp
type signResp struct { //nolint:unused,deadcode
	// in: body
	Body struct {
		// A base64-encoded signature.
		Signature string `json:"signature"`
	}
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
	Body struct {
		// A base64-encoded signature.
		Signature string `json:"signature"`

		// A base64-encoded message.
		Message string `json:"message"`
	}
}

// verifyResp model
//
// swagger:response verifyResp
type verifyResp struct{} //nolint:unused,deadcode

// encryptReq model
//
// swagger:parameters encryptReq
type encryptReq struct { //nolint:unused,deadcode
	// The key store's ID.
	//
	// in: path
	// required: true
	KeyStoreID string `json:"key_store_id"`

	// The key's ID.
	//
	// in: path
	// required: true
	KeyID string `json:"key_id"`

	// in: body
	Body struct {
		// A base64-encoded plaintext to be encrypted.
		// required: true
		Message string `json:"message"`

		// A base64-encoded associated data to be authenticated, but not encrypted.
		// Associated data is optional, so this parameter can be nil.
		AssociatedData string `json:"associated_data,omitempty"`
	}
}

// encryptResp model
//
// swagger:response encryptResp
type encryptResp struct { //nolint:unused,deadcode
	// in: body
	Body struct {
		// A base64-encoded ciphertext.
		Ciphertext string `json:"ciphertext"`

		// A base64-encoded nonce.
		Nonce string `json:"nonce"`
	}
}

// decryptReq model
//
// swagger:parameters decryptReq
type decryptReq struct { //nolint:unused,deadcode
	// The key store's ID.
	//
	// in: path
	// required: true
	KeyStoreID string `json:"key_store_id"`

	// The key's ID.
	//
	// in: path
	// required: true
	KeyID string `json:"key_id"`

	// in: body
	Body struct {
		// A base64-encoded ciphertext to be decrypted.
		// required: true
		Ciphertext string `json:"ciphertext"`

		// A base64-encoded associated data to be authenticated. For successful decryption it must be the same as
		// associated data used during encryption.
		AssociatedData string `json:"associated_data,omitempty"`

		// A base64-encoded nonce.
		// required: true
		Nonce string `json:"nonce"`
	}
}

// decryptResp model
//
// swagger:response decryptResp
type decryptResp struct { //nolint:unused,deadcode
	// in: body
	Body struct {
		// A base64-encoded plaintext.
		Plaintext string `json:"plaintext"`
	}
}

// computeMACReq model
//
// swagger:parameters computeMACReq
type computeMACReq struct { //nolint:unused,deadcode
	// The key store's ID.
	//
	// in: path
	// required: true
	KeyStoreID string `json:"key_store_id"`

	// The key's ID.
	//
	// in: path
	// required: true
	KeyID string `json:"key_id"`

	// in: body
	Body struct {
		// A base64-encoded data to compute MAC for.
		// required: true
		Data string `json:"data"`
	}
}

// computeMACResp model
//
// swagger:response computeMACResp
type computeMACResp struct { //nolint:unused,deadcode
	// in: body
	Body struct {
		// A base64-encoded MAC.
		MAC string `json:"mac"`
	}
}

// verifyMACReq model
//
// swagger:parameters verifyMACReq
type verifyMACReq struct { //nolint:unused,deadcode
	// The key store's ID.
	//
	// in: path
	// required: true
	KeyStoreID string `json:"key_store_id"`

	// The key's ID.
	//
	// in: path
	// required: true
	KeyID string `json:"key_id"`

	// in: body
	Body struct {
		// A base64-encoded MAC for data.
		// required: true
		MAC string `json:"mac"`

		// A base64-encoded data the MAC was computed for.
		// required: true
		Data string `json:"data"`
	}
}

// verifyMACResp model
//
// swagger:response verifyMACResp
type verifyMACResp struct{} //nolint:unused,deadcode

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
