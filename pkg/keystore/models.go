/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package keystore

// Configuration represents a keystore configuration.
type Configuration struct {
	// Counter for the keystore configuration to ensure that clients are properly synchronized.
	Sequence int `json:"sequence"`
	// Entity that is in control of the keystore.
	Controller string `json:"controller"`
}
