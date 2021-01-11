/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package keystore

import (
	"github.com/google/tink/go/keyset"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
)

// MockKeystore is a mock Keystore.
type MockKeystore struct {
	CreateKeyValue    string
	ExportKeyValue    []byte
	GetKeyHandleValue *keyset.Handle
	KeyManagerValue   *mockkms.KeyManager
	CreateKeyErr      error
	ExportKeyErr      error
	GetKeyHandleErr   error
}

// CreateKey creates a new key.
func (m *MockKeystore) CreateKey(kt kms.KeyType) (string, error) {
	if m.CreateKeyErr != nil {
		return "", m.CreateKeyErr
	}

	return m.CreateKeyValue, nil
}

// ExportKey exports a public key.
func (m *MockKeystore) ExportKey(keyID string) ([]byte, error) {
	if m.ExportKeyErr != nil {
		return nil, m.ExportKeyErr
	}

	return m.ExportKeyValue, nil
}

// GetKeyHandle retrieves key handle by keyID.
func (m *MockKeystore) GetKeyHandle(keyID string) (interface{}, error) {
	if m.GetKeyHandleErr != nil {
		return nil, m.GetKeyHandleErr
	}

	return m.GetKeyHandleValue, nil
}

// KeyManager returns KeyManager instance.
func (m *MockKeystore) KeyManager() kms.KeyManager {
	return m.KeyManagerValue
}
