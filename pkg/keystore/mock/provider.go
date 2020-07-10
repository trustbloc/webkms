/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mock

import (
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	mockcrypto "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	"github.com/trustbloc/edge-core/pkg/storage"
	"github.com/trustbloc/edge-core/pkg/storage/mockstore"
)

type Provider struct {
	MockStorage *mockstore.Provider
	MockKMS     *mockkms.KeyManager
	MockCrypto  crypto.Crypto
}

func NewProvider() *Provider {
	return &Provider{
		MockStorage: mockstore.NewMockStoreProvider(),
		MockKMS:     &mockkms.KeyManager{},
		MockCrypto:  &mockcrypto.Crypto{},
	}
}

func (p Provider) StorageProvider() storage.Provider {
	return p.MockStorage
}

func (p Provider) KMS() kms.KeyManager {
	return p.MockKMS
}

func (p Provider) Crypto() crypto.Crypto {
	return p.MockCrypto
}
