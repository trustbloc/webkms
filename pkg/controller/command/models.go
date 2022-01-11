/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package command

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/kms"

	"github.com/trustbloc/kms/pkg/controller/errors"
)

// WrappedRequest is a command request with a wrapped original request from user.
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
	VaultURL   string `json:"vault_url"`
	Capability []byte `json:"capability"`
}

// Validate validates CreateKeyStore request.
func (r *CreateKeyStoreRequest) Validate() error {
	if r.Controller == "" {
		return fmt.Errorf("%w: controller must be non-empty", errors.ErrValidation)
	}

	return nil
}

// CreateKeyStoreResponse is a response for CreateKeyStore request.
type CreateKeyStoreResponse struct {
	KeyStoreURL string `json:"key_store_url"`
	Capability  []byte `json:"capability,omitempty"`
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

// RotateKeyRequest is a request to rotate a key.
type RotateKeyRequest struct {
	KeyType kms.KeyType `json:"key_type"`
}

// RotateKeyResponse is a response for RotateKeyRequest request.
type RotateKeyResponse struct {
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
	Message        []byte `json:"message"`
	AssociatedData []byte `json:"associated_data,omitempty"`
}

// EncryptResponse is a response for Encrypt request.
type EncryptResponse struct {
	Ciphertext []byte `json:"ciphertext"`
	Nonce      []byte `json:"nonce"`
}

// DecryptRequest is a request to decrypt a ciphertext.
type DecryptRequest struct {
	Ciphertext     []byte `json:"ciphertext"`
	AssociatedData []byte `json:"associated_data,omitempty"`
	Nonce          []byte `json:"nonce"`
}

// DecryptResponse is a response for Decrypt request.
type DecryptResponse struct {
	Plaintext []byte `json:"plaintext"`
}

// ComputeMACRequest is a request to compute MAC for data.
type ComputeMACRequest struct {
	Data []byte `json:"data"`
}

// ComputeMACResponse is a response for ComputeMAC request.
type ComputeMACResponse struct {
	MAC []byte `json:"mac"`
}

// VerifyMACRequest is a request to verify MAC for data.
type VerifyMACRequest struct {
	MAC  []byte `json:"mac"`
	Data []byte `json:"data"`
}

// SignMultiRequest is a request to create a BBS+ signature of messages.
type SignMultiRequest struct {
	Messages [][]byte `json:"messages"`
}

// SignMultiResponse is a response for SignMulti request.
type SignMultiResponse struct {
	Signature []byte `json:"signature"`
}

// VerifyMultiRequest is a request to verify a signature of messages (BBS+).
type VerifyMultiRequest struct {
	Signature []byte   `json:"signature"`
	Messages  [][]byte `json:"messages"`
}

// DeriveProofRequest is a request to create a BBS+ signature proof for a list of revealed messages.
type DeriveProofRequest struct {
	Messages        [][]byte `json:"messages"`
	Signature       []byte   `json:"signature"`
	Nonce           []byte   `json:"nonce"`
	RevealedIndexes []int    `json:"revealed_indexes"`
}

// DeriveProofResponse is a response for DeriveProof request.
type DeriveProofResponse struct {
	Proof []byte `json:"proof"`
}

// VerifyProofRequest is a request to verify a BBS+ signature proof for revealed messages.
type VerifyProofRequest struct {
	Proof    []byte   `json:"proof"`
	Messages [][]byte `json:"messages"`
	Nonce    []byte   `json:"nonce"`
}

// EasyRequest is a request to seal payload with a provided nonce.
type EasyRequest struct {
	Payload  []byte `json:"payload"`
	Nonce    []byte `json:"nonce"`
	TheirPub []byte `json:"their_pub"`
}

// EasyResponse is a response for Easy request.
type EasyResponse struct {
	Ciphertext []byte `json:"ciphertext"`
}

// EasyOpenRequest is a request to unseal a ciphertext sealed with Easy.
type EasyOpenRequest struct {
	Ciphertext []byte `json:"ciphertext"`
	Nonce      []byte `json:"nonce"`
	TheirPub   []byte `json:"their_pub"`
	MyPub      []byte `json:"my_pub"`
}

// EasyOpenResponse is a response for EasyOpen request.
type EasyOpenResponse struct {
	Plaintext []byte `json:"plaintext"`
}

// SealOpenRequest is a request to decrypt a ciphertext encrypted with Seal.
type SealOpenRequest struct {
	Ciphertext []byte `json:"ciphertext"`
	MyPub      []byte `json:"my_pub"`
}

// SealOpenResponse is a response for SealOpen request.
type SealOpenResponse struct {
	Plaintext []byte `json:"plaintext"`
}

// WrapKeyRequest is a request to wrap CEK.
type WrapKeyRequest struct {
	CEK             []byte            `json:"cek"`
	APU             []byte            `json:"apu"`
	APV             []byte            `json:"apv"`
	RecipientPubKey *crypto.PublicKey `json:"recipient_pub_key"`
	Tag             []byte            `json:"tag,omitempty"`
}

// WrapKeyResponse is a response for WrapKey request.
type WrapKeyResponse struct {
	crypto.RecipientWrappedKey
}

// UnwrapKeyRequest is a request to unwrap a wrapped key.
type UnwrapKeyRequest struct {
	WrappedKey   crypto.RecipientWrappedKey `json:"wrapped_key"`
	SenderPubKey *crypto.PublicKey          `json:"sender_pub_key,omitempty"`
	Tag          []byte                     `json:"tag,omitempty"`
}

// UnwrapKeyResponse is a response for UnwrapKey request.
type UnwrapKeyResponse struct {
	Key []byte `json:"key"`
}
