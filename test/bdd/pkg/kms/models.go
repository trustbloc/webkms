/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

type createDIDResp struct {
	DID string `json:"did"`
}

type createKeystoreReq struct {
	Controller string      `json:"controller"`
	EDV        *edvOptions `json:"edv"`
}

type edvOptions struct {
	VaultURL   string `json:"vault_url"`
	Capability []byte `json:"capability"`
}

type createKeyStoreResp struct {
	KeyStoreURL string `json:"key_store_url"`
	Capability  []byte `json:"capability"`
}

type createKeyReq struct {
	KeyType   string `json:"key_type"`
	ExportKey bool   `json:"export"`
}

type createKeyResp struct {
	KeyURL    string `json:"key_url"`
	PublicKey []byte `json:"public_key"`
}

type exportKeyResp struct {
	PublicKey []byte `json:"public_key"`
}

type importKeyReq struct {
	Key     []byte      `json:"key"`
	KeyType kms.KeyType `json:"key_type"`
	KeyID   string      `json:"key_id,omitempty"`
}

type importKeyResp struct {
	KeyURL string `json:"key_url"`
}

type signReq struct {
	Message []byte `json:"message"`
}

type signResp struct {
	Signature []byte `json:"signature"`
}

type verifyReq struct {
	Signature []byte `json:"signature"`
	Message   []byte `json:"message"`
}

type encryptReq struct {
	Message        []byte `json:"message"`
	AssociatedData []byte `json:"associated_data,omitempty"`
}

type encryptResp struct {
	Ciphertext []byte `json:"ciphertext"`
	Nonce      []byte `json:"nonce"`
}

type decryptReq struct {
	Ciphertext     []byte `json:"ciphertext"`
	AssociatedData []byte `json:"associated_data,omitempty"`
	Nonce          []byte `json:"nonce"`
}

type decryptResp struct {
	Plaintext []byte `json:"plaintext"`
}

type computeMACReq struct {
	Data []byte `json:"data"`
}

type computeMACResp struct {
	MAC []byte `json:"mac"`
}

type verifyMACReq struct {
	MAC  []byte `json:"mac"`
	Data []byte `json:"data"`
}

type wrapReq struct {
	CEK             []byte            `json:"cek"`
	APU             []byte            `json:"apu"`
	APV             []byte            `json:"apv"`
	RecipientPubKey *crypto.PublicKey `json:"recipient_pub_key"`
	Tag             []byte            `json:"tag,omitempty"`
}

type wrapResp struct {
	crypto.RecipientWrappedKey
}

type unwrapReq struct {
	WrappedKey   crypto.RecipientWrappedKey `json:"wrapped_key"`
	SenderPubKey *crypto.PublicKey          `json:"sender_pub_key,omitempty"`
	Tag          []byte                     `json:"tag,omitempty"`
}

type unwrapResp struct {
	Key []byte `json:"key"`
}

type setSecretRequest struct {
	Secret []byte `json:"secret"`
}

type errorResponse struct {
	Message string `json:"errMessage,omitempty"`
}

type easyReq struct {
	Payload  []byte `json:"payload"`
	Nonce    []byte `json:"nonce"`
	TheirPub []byte `json:"their_pub"`
}

type easyResp struct {
	Ciphertext []byte `json:"ciphertext"`
}

type easyOpenReq struct {
	Ciphertext []byte `json:"ciphertext"`
	Nonce      []byte `json:"nonce"`
	TheirPub   []byte `json:"their_pub"`
	MyPub      []byte `json:"my_pub"`
}

type easyOpenResp struct {
	Plaintext []byte `json:"plaintext"`
}

type sealOpenReq struct {
	Ciphertext []byte `json:"ciphertext"`
	MyPub      []byte `json:"my_pub"`
}

type sealOpenResp struct {
	Plaintext []byte `json:"plaintext"`
}
