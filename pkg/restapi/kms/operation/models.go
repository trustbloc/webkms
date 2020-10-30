/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

type createKeystoreReq struct {
	Controller string `json:"controller"`
}

type createKeyReq struct {
	KeyType string `json:"keyType"`
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
