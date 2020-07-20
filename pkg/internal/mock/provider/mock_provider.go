/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package provider

import (
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	mockcrypto "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	"github.com/trustbloc/edge-core/pkg/storage"
	"github.com/trustbloc/edge-core/pkg/storage/mockstore"

	"github.com/trustbloc/hub-kms/pkg/provider"
)

type MockProvider struct {
	MockStorage   *mockstore.Provider
	MockKMS       *mockkms.KeyManager
	MockCrypto    crypto.Crypto
	KMSCreatorErr error
}

func NewMockProvider() *MockProvider {
	return &MockProvider{
		MockStorage: mockstore.NewMockStoreProvider(),
		MockKMS:     &mockkms.KeyManager{},
		MockCrypto:  &mockcrypto.Crypto{},
	}
}

func (p MockProvider) StorageProvider() storage.Provider {
	return p.MockStorage
}

func (p MockProvider) KMSCreator() provider.KMSCreator {
	return func(keystoreID string) (kms.KeyManager, error) {
		if p.KMSCreatorErr != nil {
			return nil, p.KMSCreatorErr
		}
		return p.MockKMS, nil
	}
}

func (p MockProvider) Crypto() crypto.Crypto {
	return p.MockCrypto
}
