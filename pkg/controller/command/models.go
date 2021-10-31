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
	KeyStoreURL    string          `json:"key_store_url"`
	RootCapability json.RawMessage `json:"root_capability"`
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

// ExportKeyResponse is a response for ExportKey request.
type ExportKeyResponse struct {
	PublicKey []byte `json:"public_key"`
}

// ImportKeyRequest is a request to import a key.
type ImportKeyRequest struct {
	Key     []byte      `json:"key"`
	KeyType kms.KeyType `json:"key_type"`
	KeyID   string      `json:"key_id,omitempty"`
}

// ImportKeyResponse is a response for ImportKey response.
type ImportKeyResponse struct {
	KeyURL string `json:"key_url"`
}

// SignRequest is a request to sign a message.
type SignRequest struct {
	Message []byte `json:"message"`
}

// SignResponse is a response for Sign request.
type SignResponse struct {
	Signature []byte `json:"signature"`
}
