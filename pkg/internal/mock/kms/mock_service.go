/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

// MockService is a mock KMS service.
type MockService struct {
	CreateKeyValue  string
	ExportKeyValue  []byte
	SignValue       []byte
	EncryptValue    []byte
	Nonce           []byte
	DecryptValue    []byte
	ComputeMACValue []byte
	WrapKeyValue    *crypto.RecipientWrappedKey
	CreateKeyErr    error
	UnwrapKeyValue  []byte
	ExportKeyErr    error
	SignErr         error
	VerifyErr       error
	EncryptErr      error
	DecryptErr      error
	ComputeMACErr   error
	VerifyMACErr    error
	WrapKeyErr      error
	UnwrapKeyErr    error
	EasyValue       []byte
	EasyOpenValue   []byte
	SealOpenValue   []byte
	EasyErr         error
	EasyOpenErr     error
	SealOpenErr     error
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

// ExportKey exports a public key.
func (s *MockService) ExportKey(keystoreID, keyID string) ([]byte, error) {
	if s.ExportKeyErr != nil {
		return nil, s.ExportKeyErr
	}

	return s.ExportKeyValue, nil
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

// WrapKey wraps cek for the recipient with public key 'recipientPubKey'.
func (s *MockService) WrapKey(keystoreID, keyID string, cek, apu, apv []byte,
	recipientPubKey *crypto.PublicKey) (*crypto.RecipientWrappedKey, error) {
	if s.WrapKeyErr != nil {
		return nil, s.WrapKeyErr
	}

	return s.WrapKeyValue, nil
}

// UnwrapKey unwraps a key in recipientWK.
func (s *MockService) UnwrapKey(keystoreID, keyID string, recipientWK *crypto.RecipientWrappedKey,
	senderPubKey *crypto.PublicKey) ([]byte, error) {
	if s.UnwrapKeyErr != nil {
		return nil, s.UnwrapKeyErr
	}

	return s.UnwrapKeyValue, nil
}

// Easy seals a message with a provided nonce.
func (s *MockService) Easy(keystoreID, keyID string, payload, nonce, theirPub []byte) ([]byte, error) {
	if s.EasyErr != nil {
		return nil, s.EasyErr
	}

	return s.EasyValue, nil
}

// EasyOpen unseals a message sealed with Easy, where the nonce is provided.
func (s *MockService) EasyOpen(keystoreID string, cipherText, nonce, theirPub, myPub []byte) ([]byte, error) {
	if s.EasyOpenErr != nil {
		return nil, s.EasyOpenErr
	}

	return s.EasyOpenValue, nil
}

// SealOpen decrypts a payload encrypted with Seal.
func (s *MockService) SealOpen(keystoreID string, cipher, myPub []byte) ([]byte, error) {
	if s.SealOpenErr != nil {
		return nil, s.SealOpenErr
	}

	return s.SealOpenValue, nil
}
