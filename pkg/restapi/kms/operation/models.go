/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

const (
	passphraseTag = "passphrase"
)

type createKeystoreReq struct {
	Controller string `json:"controller"`
}

type createKeyReq struct {
	KeyType string `json:"keyType"`
	lockParam
}

type signReq struct {
	Message string `json:"message"`
	lockParam
}

type signResp struct {
	Signature string `json:"signature"`
}

type verifyReq struct {
	Signature string `json:"signature"`
	Message   string `json:"message"`
	lockParam
}

type encryptReq struct {
	Message        string `json:"message"`
	AdditionalData string `json:"aad"`
	lockParam
}

type encryptResp struct {
	CipherText string `json:"cipherText"`
	Nonce      string `json:"nonce"`
}

type decryptReq struct {
	CipherText     string `json:"cipherText"`
	AdditionalData string `json:"aad"`
	Nonce          string `json:"nonce"`
	lockParam
}

type decryptResp struct {
	PlainText string `json:"plainText"`
}

type computeMACReq struct {
	Data string `json:"data"`
	lockParam
}

type computeMACResp struct {
	MAC string `json:"mac"`
}

type verifyMACReq struct {
	MAC  string `json:"mac"`
	Data string `json:"data"`
	lockParam
}

type lockParam struct {
	Passphrase string `json:"passphrase"`
}
