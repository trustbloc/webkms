/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package command

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/kms"

	"github.com/trustbloc/kms/pkg/controller/errors"
)

// WrappedRequest is a command request with wrapped original request from user.
type WrappedRequest struct {
	KeyStoreID  string `json:"key_store_id"`
	KeyID       string `json:"key_id"`
	User        string `json:"user"`
	SecretShare []byte `json:"secret_share"`
	Request     []byte `json:"request"`
}

// CreateDIDResponse is a response for CreateDID request.
type CreateDIDResponse struct {
	DID string `json:"did"`
}

// CreateKeyStoreRequest is a request to create user's key store.
type CreateKeyStoreRequest struct {
	Controller string      `json:"controller"`
	EDV        *EDVOptions `json:"edv"`
}

// EDVOptions represents options for creating data vault on EDV.
type EDVOptions struct {
	VaultURL   string          `json:"vault_url"`
	Capability json.RawMessage `json:"capability"`
}

// Validate validates CreateKeyStore request.
func (r *CreateKeyStoreRequest) Validate() error {
	if r == nil {
		return fmt.Errorf("%w: validate on nil value", errors.ErrValidation)
	}

	if r.Controller == "" {
		return fmt.Errorf("%w: controller must be non-empty", errors.ErrValidation)
	}

	return nil
}

// CreateKeyStoreResponse is a response for CreateKeyStore request.
type CreateKeyStoreResponse struct {
	KeyStoreURL    string `json:"key_store_url"`
	RootCapability []byte `json:"root_capability"`
}

// CreateKeyRequest is a request to create a key.
type CreateKeyRequest struct {
	KeyType kms.KeyType `json:"key_type"`
}

// CreateKeyResponse is a response for CreateKey request.
type CreateKeyResponse struct {
	KeyURL    string `json:"key_url"`
	PublicKey []byte `json:"public_key"`
}

// ImportKeyRequest is a request to import a key.
type ImportKeyRequest struct {
	Key     []byte      `json:"key"`
	KeyType kms.KeyType `json:"key_type"`
	KeyID   string      `json:"key_id,omitempty"`
}

// ImportKeyResponse is a response for ImportKey request.
type ImportKeyResponse struct {
	KeyURL string `json:"key_url"`
}

// ExportKeyResponse is a response for ExportKey request.
type ExportKeyResponse struct {
	PublicKey []byte `json:"public_key"`
}

// SignRequest is a request to sign a message.
type SignRequest struct {
	Message []byte `json:"message"`
}

// SignResponse is a response for Sign request.
type SignResponse struct {
	Signature []byte `json:"signature"`
}

// VerifyRequest is a request to verify a signature.
type VerifyRequest struct {
	Signature []byte `json:"signature"`
	Message   []byte `json:"message"`
}

// EncryptRequest is a request to encrypt a message with associated data.
type EncryptRequest struct {
	// Message is the plaintext to be encrypted. It must be non-nil.
	Message []byte `json:"message"`
	// AssociatedData to be authenticated, but not encrypted. Associated data is optional, so this parameter can be nil.
	// For successful decryption the same associated data must be provided along with the ciphertext and nonce.
	AssociatedData []byte `json:"associated_data,omitempty"`
}

// EncryptResponse is a response for Encrypt request.
type EncryptResponse struct {
	Ciphertext []byte `json:"ciphertext"`
	Nonce      []byte `json:"nonce"`
}

// DecryptRequest is a request to decrypt a ciphertext.
type DecryptRequest struct {
	// Ciphertext to be decrypted. It must be non-nil.
	Ciphertext []byte `json:"ciphertext"`
	// AssociatedData to be authenticated. For successful decryption it must be the same as associated data used
	// during encryption.
	AssociatedData []byte `json:"associated_data,omitempty"`
	Nonce          []byte `json:"nonce"`
}

// DecryptResponse is a response for Decrypt request.
type DecryptResponse struct {
	Plaintext []byte `json:"plaintext"`
}
