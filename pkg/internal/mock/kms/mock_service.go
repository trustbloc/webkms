/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"net/http"

	mockcrypto "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"

	"github.com/trustbloc/hub-kms/pkg/keystore"
	"github.com/trustbloc/hub-kms/pkg/kms"
)

var _ kms.Service = (*MockService)(nil)

// MockService is a mock KMS service.
type MockService struct {
	CreateKeystoreValue  *kms.KeystoreData
	ResolveKeystoreValue keystore.Keystore
	GetKeystoreDataValue *kms.KeystoreData
	CreateKeystoreErr    error
	ResolveKeystoreErr   error
	GetKeystoreDataErr   error
	SaveKeystoreDataErr  error
	mockcrypto.Crypto
}

// CreateKeystore creates a new Keystore.
func (s *MockService) CreateKeystore(controller, vaultID string) (*kms.KeystoreData, error) {
	if s.CreateKeystoreErr != nil {
		return nil, s.CreateKeystoreErr
	}

	return s.CreateKeystoreValue, nil
}

// ResolveKeystore resolves Keystore for the given request.
func (s *MockService) ResolveKeystore(req *http.Request) (keystore.Keystore, error) {
	if s.ResolveKeystoreErr != nil {
		return nil, s.ResolveKeystoreErr
	}

	return s.ResolveKeystoreValue, nil
}

// GetKeystoreData retrieves Keystore metadata.
func (s *MockService) GetKeystoreData(keystoreID string) (*kms.KeystoreData, error) {
	if s.GetKeystoreDataErr != nil {
		return nil, s.GetKeystoreDataErr
	}

	return s.GetKeystoreDataValue, nil
}

// SaveKeystoreData saves Keystore metadata.
func (s *MockService) SaveKeystoreData(keystoreData *kms.KeystoreData) error {
	if s.SaveKeystoreDataErr != nil {
		return s.SaveKeystoreDataErr
	}

	return nil
}
