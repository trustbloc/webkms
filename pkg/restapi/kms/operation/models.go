/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

type createKeystoreReq struct {
	Controller string `json:"controller"`
}

type createKeyReq struct {
	KeystoreID string `json:"keystoreID"`
	KeyType    string `json:"keyType"`
	Passphrase string `json:"passphrase"`
}
