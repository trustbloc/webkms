/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package keystore

const (
	testKeystoreID = "keystoreID"
)

// MockService is a mock Keystore service.
type MockService struct {
	CreateErr error
}

// NewMockService returns a new mock Keystore service.
func NewMockService() *MockService {
	return &MockService{}
}

// Create creates a new keystore.
func (s MockService) Create(_ string) (string, error) {
	if s.CreateErr != nil {
		return "", s.CreateErr
	}

	return testKeystoreID, nil
}
