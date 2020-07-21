/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package provider

import (
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/trustbloc/edge-core/pkg/storage"
)

// Provider represents provider with functionality needed for keystore.
type Provider interface {
	StorageProvider() storage.Provider
	KMSCreator() KMSCreator
	Crypto() crypto.Crypto
}

// KMSCreator provides method to create a new key management service for keystore.
type KMSCreator func(keystoreID string) (kms.KeyManager, error)
