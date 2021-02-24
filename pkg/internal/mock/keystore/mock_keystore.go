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
	CreateKeyValue             string
	ExportKeyValue             []byte
	CreateAndExportKeyID       string
	CreateAndExportPubKeyValue []byte
	ImportKeyID                string
	GetKeyHandleValue          *keyset.Handle
	KeyManagerValue            *mockkms.KeyManager
	CreateKeyErr               error
	ExportKeyErr               error
	CreateAndExportKeyErr      error
	ImportKeyErr               error
	GetKeyHandleErr            error
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

// CreateAndExportKey creates a new key and exports its public part.
func (m *MockKeystore) CreateAndExportKey(kt kms.KeyType) (string, []byte, error) {
	if m.CreateAndExportKeyErr != nil {
		return "", nil, m.CreateAndExportKeyErr
	}

	return m.CreateAndExportKeyID, m.CreateAndExportPubKeyValue, nil
}

// ImportKey imports private key bytes (in DER format) of kt type into KMS and returns key ID.
func (m *MockKeystore) ImportKey(der []byte, kt kms.KeyType) (string, error) {
	if m.ImportKeyErr != nil {
		return "", m.ImportKeyErr
	}

	return m.ImportKeyID, nil
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
