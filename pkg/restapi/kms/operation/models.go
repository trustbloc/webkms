/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import "encoding/json"

// CreateKeystoreReq create key store request.
type CreateKeystoreReq struct {
	Controller         string `json:"controller"`
	OperationalVaultID string `json:"operationalVaultID"`
}

// UpdateCapabilityReq update capability request.
type UpdateCapabilityReq struct {
	OperationalEDVCapability json.RawMessage `json:"operationalEDVCapability,omitempty"`
}

type createKeyReq struct {
	KeyType string `json:"keyType"`
}

type exportKeyResp struct {
	PublicKey string `json:"publicKey"`
}

type signReq struct {
	Message string `json:"message"`
}

type signResp struct {
	Signature string `json:"signature"`
}

type verifyReq struct {
	Signature string `json:"signature"`
	Message   string `json:"message"`
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

type publicKey struct {
	KID   string `json:"kid,omitempty"`
	X     string `json:"x,omitempty"`
	Y     string `json:"y,omitempty"`
	Curve string `json:"curve,omitempty"`
	Type  string `json:"type,omitempty"`
}

type wrapReq struct {
	CEK             string    `json:"cek,omitempty"`
	APU             string    `json:"apu,omitempty"`
	APV             string    `json:"apv,omitempty"`
	RecipientPubKey publicKey `json:"recpubkey,omitempty"`
	SenderKID       string    `json:"senderkid,omitempty"`
}

type wrapResp struct {
	WrappedKey recipientWrappedKey `json:"wrappedKey,omitempty"`
}

type recipientWrappedKey struct {
	KID          string    `json:"kid,omitempty"`
	EncryptedCEK string    `json:"encryptedcek,omitempty"`
	EPK          publicKey `json:"epk,omitempty"`
	Alg          string    `json:"alg,omitempty"`
	APU          string    `json:"apu,omitempty"`
	APV          string    `json:"apv,omitempty"`
}

type unwrapReq struct {
	WrappedKey recipientWrappedKey `json:"wrappedKey,omitempty"`
	SenderKID  string              `json:"senderkid,omitempty"`
}

type unwrapResp struct {
	Key string `json:"key,omitempty"`
}
