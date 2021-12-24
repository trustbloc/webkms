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

// rotateKeyReq model
//
// swagger:parameters rotateKeyReq
type rotateKeyReq struct { //nolint:unused,deadcode
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

		// A type on new key.
		// required: true
		KeyType string `json:"key_type"`
	}
}

// rotateKeyResp model
//
// swagger:response rotateKeyResp
type rotateKeyResp struct { //nolint:unused,deadcode
	// in: body
	Body struct {
		// URL of rotated key.
		KeyURL string `json:"key_url"`
	}
}

// signReq model
//
// swagger:parameters signReq
type signReq struct { //nolint:unused,deadcode
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

// signMultiReq model
//
// swagger:parameters signMultiReq
type signMultiReq struct { //nolint:unused,deadcode
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
		// Base64-encoded messages to sign.
		Messages []string `json:"messages"`
	}
}

// signMultiResp model
//
// swagger:response signMultiResp
type signMultiResp struct { //nolint:unused,deadcode
	// in: body
	Body struct {
		// A base64-encoded signature.
		Signature string `json:"signature"`
	}
}

// verifyMultiReq model
//
// swagger:parameters verifyMultiReq
type verifyMultiReq struct { //nolint:unused,deadcode
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
		// A base64-encoded signature.
		Signature string `json:"signature"`

		// Base64-encoded messages to verify.
		Messages []string `json:"messages"`
	}
}

// verifyMultiResp model
//
// swagger:response verifyMultiResp
type verifyMultiResp struct{} //nolint:unused,deadcode

// deriveProofReq model
//
// swagger:parameters deriveProofReq
type deriveProofReq struct { //nolint:unused,deadcode
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
		// Base64-encoded messages.
		// required: true
		Messages []string `json:"messages"`

		// A base64-encoded signature.
		// required: true
		Signature string `json:"signature"`

		// A base64-encoded nonce.
		// required: true
		Nonce string `json:"nonce"`

		// A vector of revealed messages.
		// required: true
		RevealedIndexes []int `json:"revealed_indexes"`
	}
}

// deriveProofResp model
//
// swagger:response deriveProofResp
type deriveProofResp struct { //nolint:unused,deadcode
	// in: body
	Body struct {
		// A base64-encoded BBS+ signature proof.
		Proof string `json:"proof"`
	}
}

// verifyProofReq model
//
// swagger:parameters verifyProofReq
type verifyProofReq struct { //nolint:unused,deadcode
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
		// A base64-encoded proof.
		// required: true
		Proof string `json:"proof"`

		// Base64-encoded messages.
		// required: true
		Messages []string `json:"messages"`

		// A base64-encoded nonce.
		// required: true
		Nonce string `json:"nonce"`
	}
}

// verifyProofResp model
//
// swagger:response verifyProofResp
type verifyProofResp struct{} //nolint:unused,deadcode

// easyReq model
//
// swagger:parameters easyReq
type easyReq struct { //nolint:unused,deadcode
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
		// A base64-encoded payload.
		// required: true
		Payload string `json:"payload"`

		// A base64-encoded nonce.
		// required: true
		Nonce string `json:"nonce"`

		// A base64-encoded public key.
		// required: true
		TheirPub string `json:"their_pub"`
	}
}

// easyResp model
//
// swagger:response easyResp
type easyResp struct { //nolint:unused,deadcode
	// in: body
	Body struct {
		// A base64-encoded ciphertext.
		Ciphertext string `json:"ciphertext"`
	}
}

// easyOpenReq model
//
// swagger:parameters easyOpenReq
type easyOpenReq struct { //nolint:unused,deadcode
	// The key store's ID.
	//
	// in: path
	// required: true
	KeyStoreID string `json:"key_store_id"`

	// in: body
	Body struct {
		// A base64-encoded ciphertext.
		// required: true
		Ciphertext string `json:"ciphertext"`

		// A base64-encoded nonce.
		// required: true
		Nonce string `json:"nonce"`

		// A base64-encoded their public key.
		// required: true
		TheirPub string `json:"their_pub"`

		// A base64-encoded my public key.
		// required: true
		MyPub string `json:"my_pub"`
	}
}

// easyOpenResp model
//
// swagger:response easyOpenResp
type easyOpenResp struct { //nolint:unused,deadcode
	// in: body
	Body struct {
		// A base64-encoded plaintext.
		Plaintext string `json:"plaintext"`
	}
}

// sealOpenReq model
//
// swagger:parameters sealOpenReq
type sealOpenReq struct { //nolint:unused,deadcode
	// The key store's ID.
	//
	// in: path
	// required: true
	KeyStoreID string `json:"key_store_id"`

	// in: body
	Body struct {
		// A base64-encoded ciphertext.
		// required: true
		Ciphertext string `json:"ciphertext"`

		// A base64-encoded my public key.
		// required: true
		MyPub string `json:"my_pub"`
	}
}

// sealOpenResp model
//
// swagger:response sealOpenResp
type sealOpenResp struct { //nolint:unused,deadcode
	// in: body
	Body struct {
		// A base64-encoded plaintext.
		Plaintext string `json:"plaintext"`
	}
}

type publicKey struct { //nolint:unused
	// Key ID.
	// required: true
	KID string `json:"kid"`

	// A base64-encoded X.
	// required: true
	X string `json:"x"`

	// A base64-encoded Y.
	// required: true
	Y string `json:"y"`

	// Curve.
	// required: true
	Curve string `json:"curve"`

	// Key type.
	// required: true
	Type string `json:"type"`
}

type wrappedKey struct { //nolint:unused
	// Key ID.
	// required: true
	KID string `json:"kid"`

	// A base64-encoded encrypted CEK.
	// required: true
	EncryptedCEK string `json:"encryptedcek"`

	// Ephemeral public key.
	// required: true
	EPK publicKey `json:"epk"`

	// Algorithm.
	// required: true
	Alg string `json:"alg"`

	// A base64-encoded APU.
	// required: true
	APU string `json:"apu"`

	// A base64-encoded APV.
	// required: true
	APV string `json:"apv"`
}

// wrapKeyReq model
//
// swagger:parameters wrapKeyReq
type wrapKeyReq struct { //nolint:unused,deadcode
	// The key store's ID.
	//
	// in: path
	// required: true
	KeyStoreID string `json:"key_store_id"`

	// in: body
	Body struct {
		// A base64-encoded CEK.
		// required: true
		CEK string `json:"cek"`

		// A base64-encoded APU.
		// required: true
		APU string `json:"apu"`

		// A base64-encoded APV.
		// required: true
		APV string `json:"apv"`

		// Recipient public key.
		// required: true
		RecipientPubKey publicKey `json:"recipient_pub_key"`
	}
}

// wrapKeyAEReq model
//
// swagger:parameters wrapKeyAEReq
type wrapKeyAEReq struct { //nolint:unused,deadcode
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
		// A base64-encoded CEK.
		// required: true
		CEK string `json:"cek"`

		// A base64-encoded APU.
		// required: true
		APU string `json:"apu"`

		// A base64-encoded APV.
		// required: true
		APV string `json:"apv"`

		// Recipient public key.
		// required: true
		RecipientPubKey publicKey `json:"recipient_pub_key"`

		// A base64-encoded authentication tag.
		// required: true
		Tag string `json:"tag"`
	}
}

// wrapKeyResp model
//
// swagger:response wrapKeyResp
type wrapKeyResp struct { //nolint:unused,deadcode
	// in: body
	Body struct {
		wrappedKey
	}
}

// unwrapKeyReq model
//
// swagger:parameters unwrapKeyReq
type unwrapKeyReq struct { //nolint:unused,deadcode
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
		// Wrapped key.
		// required: true
		WrappedKey wrappedKey `json:"wrapped_key"`

		// Sender's public key used for ECDH-1PU key agreement for authenticating the sender.
		// required: true
		SenderPubKey *publicKey `json:"sender_pub_key,omitempty"`

		// A base64-encoded authentication tag.
		// required: true
		Tag string `json:"tag,omitempty"`
	}
}

// unwrapKeyResp model
//
// swagger:response unwrapKeyResp
type unwrapKeyResp struct { //nolint:unused,deadcode
	// in: body
	Body struct {
		// A base64-encoded unwrapped key.
		Key string `json:"key"`
	}
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
