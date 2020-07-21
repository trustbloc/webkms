/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

type createKeystoreReq struct {
	// Sequence is a counter for the keystore configuration to ensure that clients are properly synchronized.
	Sequence int `json:"sequence"`
	// Controller is an entity that is in control of the keystore.
	Controller string `json:"controller"`
}

type createKeyReq struct {
	KeystoreID string `json:"keystoreID"`
	KeyType    string `json:"keyType"`
}
