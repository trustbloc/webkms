/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	arieskms "github.com/hyperledger/aries-framework-go/pkg/kms"
	mockcrypto "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"

	mockkeystore "github.com/trustbloc/hub-kms/pkg/internal/mock/keystore"
	"github.com/trustbloc/hub-kms/pkg/keystore"
	"github.com/trustbloc/hub-kms/pkg/kms"
)

// MockProvider is a mock Provider for KMS service.
type MockProvider struct {
	MockKeystoreService *mockkeystore.MockService
	MockKeyManager      *mockkms.KeyManager
	MockCrypto          *mockcrypto.Crypto
	MockCryptoBox       *MockCryptoBox
}

// NewMockProvider returns a new mock Provider for the KMS service.
func NewMockProvider() *MockProvider {
	return &MockProvider{
		MockKeystoreService: mockkeystore.NewMockService(),
		MockKeyManager:      &mockkms.KeyManager{},
		MockCrypto:          &mockcrypto.Crypto{},
		MockCryptoBox:       &MockCryptoBox{},
	}
}

// KeystoreService gets the Keystore service instance.
func (p *MockProvider) KeystoreService() keystore.Service {
	return p.MockKeystoreService
}

// KeyManager gets the KeyManager instance.
func (p *MockProvider) KeyManager() arieskms.KeyManager {
	return p.MockKeyManager
}

// Crypto gets the Crypto instance.
func (p *MockProvider) Crypto() crypto.Crypto {
	return p.MockCrypto
}

// CryptoBox gets the CryptoBox instance.
func (p *MockProvider) CryptoBox() kms.CryptoBox {
	return p.MockCryptoBox
}
