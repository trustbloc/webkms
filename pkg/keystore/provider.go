/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package keystore

// Provider represents functionality needed for keystore.
type Provider interface {
	// CreateStore creates a new keystore with the given name.
	CreateStore(name string) error
}
