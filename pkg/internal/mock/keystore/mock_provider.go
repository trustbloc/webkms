/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package keystore

import (
	arieskms "github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	"github.com/trustbloc/edge-core/pkg/storage"
	"github.com/trustbloc/edge-core/pkg/storage/mockstore"
)

// MockProvider is a mock Provider for the Keystore service.
type MockProvider struct {
	MockStorageProvider    *mockstore.Provider
	MockKeyManagerProvider *kms.Provider
	MockKeyManager         *kms.KeyManager
	KeyManagerCreatorError error
}

// NewMockProvider returns a new mock Provider for the Keystore service.
func NewMockProvider() *MockProvider {
	return &MockProvider{
		MockStorageProvider:    mockstore.NewMockStoreProvider(),
		MockKeyManagerProvider: &kms.Provider{},
		MockKeyManager:         &kms.KeyManager{},
	}
}

// StorageProvider returns storage Provider instance.
func (p *MockProvider) StorageProvider() storage.Provider {
	return p.MockStorageProvider
}

// KeyManagerProvider returns key manager Provider instance.
func (p *MockProvider) KeyManagerProvider() arieskms.Provider {
	return p.MockKeyManagerProvider
}

// KeyManagerCreator returns key manager Creator.
func (p *MockProvider) KeyManagerCreator() arieskms.Creator {
	return func(provider arieskms.Provider) (arieskms.KeyManager, error) {
		if p.KeyManagerCreatorError != nil {
			return nil, p.KeyManagerCreatorError
		}

		return p.MockKeyManager, nil
	}
}
