/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package keystore

import (
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

// MockProvider is a mock Provider for the Keystore service.
type MockProvider struct {
	MockStorageProvider    *mockstorage.MockStoreProvider
	MockKeyManagerProvider *mockkms.Provider
	MockKeyManager         *mockkms.KeyManager
	KeyManagerCreatorError error
}

// NewMockProvider returns a new mock Provider for the Keystore service.
func NewMockProvider() *MockProvider {
	return &MockProvider{
		MockStorageProvider:    mockstorage.NewMockStoreProvider(),
		MockKeyManagerProvider: &mockkms.Provider{},
		MockKeyManager:         &mockkms.KeyManager{},
	}
}

// StorageProvider returns storage Provider instance.
func (p *MockProvider) StorageProvider() storage.Provider {
	return p.MockStorageProvider
}

// KMSProvider returns KMS provider instance.
func (p *MockProvider) KMSProvider() kms.Provider {
	return p.MockKeyManagerProvider
}

// KMSCreator returns KMS creator.
func (p *MockProvider) KMSCreator() kms.Creator {
	return func(provider kms.Provider) (kms.KeyManager, error) {
		if p.KeyManagerCreatorError != nil {
			return nil, p.KeyManagerCreatorError
		}

		return p.MockKeyManager, nil
	}
}
