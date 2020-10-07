/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	mockcrypto "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	"github.com/trustbloc/edge-core/pkg/storage"
	"github.com/trustbloc/edge-core/pkg/storage/mockstore"
)

// MockProvider is a mock Operation Provider.
type MockProvider struct {
	MockStorage   *mockstore.Provider
	MockKMS       *mockkms.KeyManager
	MockCrypto    *mockcrypto.Crypto
	KMSCreatorErr error
}

// NewMockProvider returns a new mock Operation Provider.
func NewMockProvider() *MockProvider {
	return &MockProvider{
		MockStorage: mockstore.NewMockStoreProvider(),
		MockKMS:     &mockkms.KeyManager{},
		MockCrypto:  &mockcrypto.Crypto{},
	}
}

// StorageProvider gets the Storage Provider instance.
func (p MockProvider) StorageProvider() storage.Provider {
	return p.MockStorage
}

// KMSCreator gets the KMS Creator instance.
func (p MockProvider) KMSCreator() KMSCreator {
	return func(ctx KMSCreatorContext) (kms.KeyManager, error) {
		if p.KMSCreatorErr != nil {
			return nil, p.KMSCreatorErr
		}

		return p.MockKMS, nil
	}
}

// Crypto gets the Crypto instance.
func (p MockProvider) Crypto() crypto.Crypto {
	return p.MockCrypto
}
