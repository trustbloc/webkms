/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package models

// KeystoreConfiguration represents a keystore configuration.
type KeystoreConfiguration struct {
	Sequence   int    `json:"sequence"`
	Controller string `json:"controller"`
}
