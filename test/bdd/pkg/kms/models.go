/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import "github.com/hyperledger/aries-framework-go/pkg/kms"

type createKeystoreReq struct {
	Controller string `json:"controller"`
	VaultID    string `json:"vaultID"`
}

type createKeyStoreResp struct {
	KeyStoreURL    string `json:"key_store_url"`
	RootCapability []byte `json:"root_capability"`
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
	Message        string `json:"message"`
	AdditionalData string `json:"aad"`
}

type encryptResp struct {
	CipherText string `json:"cipherText"`
	Nonce      string `json:"nonce"`
}

type decryptReq struct {
	CipherText     string `json:"cipherText"`
	AdditionalData string `json:"aad"`
	Nonce          string `json:"nonce"`
}

type decryptResp struct {
	PlainText string `json:"plainText"`
}

type computeMACReq struct {
	Data string `json:"data"`
}

type computeMACResp struct {
	MAC string `json:"mac"`
}

type verifyMACReq struct {
	MAC  string `json:"mac"`
	Data string `json:"data"`
}

type wrapReq struct {
	CEK             string       `json:"cek,omitempty"`
	APU             string       `json:"apu,omitempty"`
	APV             string       `json:"apv,omitempty"`
	RecipientPubKey publicKeyReq `json:"recPubKey,omitempty"`
	SenderKID       string       `json:"senderKID,omitempty"`
}

type wrapResp struct {
	WrappedKey recipientWrappedKey `json:"wrappedKey,omitempty"`
}

type recipientWrappedKey struct {
	KID          string       `json:"kid,omitempty"`
	EncryptedCEK string       `json:"encryptedCEK,omitempty"`
	EPK          publicKeyReq `json:"epk,omitempty"`
	Alg          string       `json:"alg,omitempty"`
	APU          string       `json:"apu,omitempty"`
	APV          string       `json:"apv,omitempty"`
}

type unwrapReq struct {
	WrappedKey recipientWrappedKey `json:"wrappedKey,omitempty"`
	SenderKID  string              `json:"senderKID,omitempty"`
}

type unwrapResp struct {
	Key string `json:"key,omitempty"`
}

type publicKeyReq struct {
	KID   string `json:"kid,omitempty"`
	X     string `json:"x,omitempty"`
	Y     string `json:"y,omitempty"`
	Curve string `json:"curve,omitempty"`
	Type  string `json:"type,omitempty"`
}

type publicKey struct {
	KID   string `json:"kid,omitempty"`
	X     []byte `json:"x,omitempty"`
	Y     []byte `json:"y,omitempty"`
	Curve string `json:"curve,omitempty"`
	Type  string `json:"type,omitempty"`
}

type setSecretRequest struct {
	Secret []byte `json:"secret"`
}

type errorResponse struct {
	Message string `json:"errMessage,omitempty"`
}

type easyReq struct {
	Payload  string `json:"payload"`
	Nonce    string `json:"nonce"`
	TheirPub string `json:"theirPub"`
}

type easyResp struct {
	CipherText string `json:"cipherText"`
}

type easyOpenReq struct {
	CipherText string `json:"cipherText"`
	Nonce      string `json:"nonce"`
	TheirPub   string `json:"theirPub"`
	MyPub      string `json:"myPub"`
}

type easyOpenResp struct {
	PlainText string `json:"plainText"`
}

type sealOpenReq struct {
	CipherText string `json:"cipherText"`
	MyPub      string `json:"myPub"`
}

type sealOpenResp struct {
	PlainText string `json:"plainText"`
}
