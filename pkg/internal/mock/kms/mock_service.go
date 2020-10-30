/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import "github.com/hyperledger/aries-framework-go/pkg/kms"

// MockService is a mock KMS service.
type MockService struct {
	CreateKeyValue  string
	SignValue       []byte
	EncryptValue    []byte
	Nonce           []byte
	DecryptValue    []byte
	ComputeMACValue []byte
	CreateKeyErr    error
	SignErr         error
	VerifyErr       error
	EncryptErr      error
	DecryptErr      error
	ComputeMACErr   error
	VerifyMACErr    error
}

// NewMockService returns a new mock KMS service.
func NewMockService() *MockService {
	return &MockService{}
}

// CreateKey creates a new key.
func (s *MockService) CreateKey(keystoreID string, kt kms.KeyType) (string, error) {
	if s.CreateKeyErr != nil {
		return "", s.CreateKeyErr
	}

	return s.CreateKeyValue, nil
}

// Sign signs a message.
func (s *MockService) Sign(keystoreID, keyID string, msg []byte) ([]byte, error) {
	if s.SignErr != nil {
		return nil, s.SignErr
	}

	return s.SignValue, nil
}

// Verify verifies a signature for the given message.
func (s *MockService) Verify(keystoreID, keyID string, sig, msg []byte) error {
	if s.VerifyErr != nil {
		return s.VerifyErr
	}

	return nil
}

// Encrypt encrypts a message with aad.
func (s *MockService) Encrypt(keystoreID, keyID string, msg, aad []byte) ([]byte, []byte, error) {
	if s.EncryptErr != nil {
		return nil, nil, s.EncryptErr
	}

	return s.EncryptValue, s.Nonce, nil
}

// Decrypt decrypts a cipher with aad and given nonce.
func (s *MockService) Decrypt(keystoreID, keyID string, cipher, aad, nonce []byte) ([]byte, error) {
	if s.DecryptErr != nil {
		return nil, s.DecryptErr
	}

	return s.DecryptValue, nil
}

// ComputeMAC computes message authentication code (MAC) for data.
func (s *MockService) ComputeMAC(keystoreID, keyID string, data []byte) ([]byte, error) {
	if s.ComputeMACErr != nil {
		return nil, s.ComputeMACErr
	}

	return s.ComputeMACValue, nil
}

// VerifyMAC determines if mac is a correct authentication code (MAC) for data.
func (s *MockService) VerifyMAC(keystoreID, keyID string, mac, data []byte) error {
	if s.VerifyMACErr != nil {
		return s.VerifyMACErr
	}

	return nil
}
