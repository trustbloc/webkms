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
	lockArg
}

type signReq struct {
	Message string `json:"message"`
	lockArg
}

type verifyReq struct {
	Signature string `json:"signature"`
	Message   string `json:"message"`
	lockArg
}

type lockArg struct {
	Passphrase string `json:"passphrase"`
}
