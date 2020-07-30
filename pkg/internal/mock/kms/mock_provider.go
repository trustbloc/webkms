/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	mockcrypto "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"

	mockkeystore "github.com/trustbloc/hub-kms/pkg/internal/mock/keystore"
	"github.com/trustbloc/hub-kms/pkg/keystore"
)

type MockProvider struct {
	MockKeystore *mockkeystore.MockRepository
	MockKMS      *mockkms.KeyManager
	MockCrypto   *mockcrypto.Crypto
}

func NewMockProvider() *MockProvider {
	return &MockProvider{
		MockKeystore: mockkeystore.NewMockRepository(),
		MockKMS:      &mockkms.KeyManager{},
		MockCrypto:   &mockcrypto.Crypto{},
	}
}

func (p *MockProvider) Keystore() keystore.Repository {
	return p.MockKeystore
}

func (p *MockProvider) KMS() kms.KeyManager {
	return p.MockKMS
}

func (p *MockProvider) Crypto() crypto.Crypto {
	return p.MockCrypto
}
