/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package keystore

import (
	"context"

	"github.com/google/tink/go/keyset"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"

	"github.com/trustbloc/hub-kms/pkg/keystore"
)

// MockService is a mock Keystore service.
type MockService struct {
	CreateKeystoreValue *keystore.Keystore
	GetKeystoreValue    *keystore.Keystore
	GetKeyHandleValue   *keyset.Handle
	KeyManagerValue     *mockkms.KeyManager
	CreateErr           error
	GetErr              error
	SaveErr             error
	GetKeyHandleErr     error
	KeyManagerErr       error
}

// NewMockService returns a new mock Keystore service.
func NewMockService() *MockService {
	return &MockService{}
}

// Create creates a new Keystore.
func (s *MockService) Create(context.Context, ...keystore.Option) (*keystore.Keystore, error) {
	if s.CreateErr != nil {
		return nil, s.CreateErr
	}

	return s.CreateKeystoreValue, nil
}

// Get retrieves Keystore by ID.
func (s *MockService) Get(context.Context, string) (*keystore.Keystore, error) {
	if s.GetErr != nil {
		return nil, s.GetErr
	}

	return s.GetKeystoreValue, nil
}

// Save stores Keystore.
func (s *MockService) Save(context.Context, *keystore.Keystore) error {
	if s.SaveErr != nil {
		return s.SaveErr
	}

	return nil
}

// GetKeyHandle retrieves key handle by keyID.
func (s *MockService) GetKeyHandle(context.Context, string) (interface{}, error) {
	if s.GetKeyHandleErr != nil {
		return nil, s.GetKeyHandleErr
	}

	return s.GetKeyHandleValue, nil
}

// KeyManager returns KeyManager instance.
func (s *MockService) KeyManager() (kms.KeyManager, error) {
	if s.KeyManagerErr != nil {
		return nil, s.KeyManagerErr
	}

	return s.KeyManagerValue, nil
}
