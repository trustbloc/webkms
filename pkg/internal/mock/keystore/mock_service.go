/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package keystore

import "github.com/trustbloc/hub-kms/pkg/keystore"

// MockService is a mock Keystore service.
type MockService struct {
	CreateKeystore *keystore.Keystore
	GetKeystore    *keystore.Keystore
	CreateErr      error
	GetErr         error
	SaveErr        error
}

// NewMockService returns a new mock Keystore service.
func NewMockService() *MockService {
	return &MockService{}
}

// Create creates a new Keystore.
func (s *MockService) Create(options ...keystore.Option) (*keystore.Keystore, error) {
	if s.CreateErr != nil {
		return nil, s.CreateErr
	}

	return s.CreateKeystore, nil
}

// Get retrieves Keystore by ID.
func (s *MockService) Get(keystoreID string) (*keystore.Keystore, error) {
	if s.GetErr != nil {
		return nil, s.GetErr
	}

	return s.GetKeystore, nil
}

// Save stores Keystore.
func (s *MockService) Save(k *keystore.Keystore) error {
	if s.SaveErr != nil {
		return s.SaveErr
	}

	return nil
}
