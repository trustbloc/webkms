/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"github.com/google/tink/go/keyset"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/kms"

	"github.com/trustbloc/hub-kms/pkg/keystore"
)

// Service provides kms/crypto functionality.
type Service interface {
	CreateKey(keystoreID string, kt kms.KeyType) (string, error)
	Sign(keystoreID, keyID string, msg []byte) ([]byte, error)
	Verify(keystoreID, keyID string, sig, msg []byte) error
	Encrypt(keystoreID, keyID string, msg, aad []byte) ([]byte, []byte, error)
	Decrypt(keystoreID, keyID string, cipher, aad, nonce []byte) ([]byte, error)
	ComputeMAC(keystoreID, keyID string, data []byte) ([]byte, error)
	VerifyMAC(keystoreID, keyID string, mac, data []byte) error
}

// Provider contains dependencies for the KMS service.
type Provider interface {
	KeystoreService() keystore.Service
	OperationalKeyManager() kms.KeyManager
	Crypto() crypto.Crypto
}

type service struct {
	keystore   keystore.Service
	keyManager kms.KeyManager
	crypto     crypto.Crypto
}

// NewService returns a new Service instance.
func NewService(provider Provider) Service {
	return &service{
		keystore:   provider.KeystoreService(),
		keyManager: provider.OperationalKeyManager(),
		crypto:     provider.Crypto(),
	}
}

// CreateKey creates a new operational key and associates it with Keystore.
func (s *service) CreateKey(keystoreID string, kt kms.KeyType) (string, error) {
	keyID, _, err := s.keyManager.Create(kt)
	if err != nil {
		return "", NewServiceError(createKeyFailed, err)
	}

	k, err := s.keystore.Get(keystoreID)
	if err != nil {
		return "", NewServiceError(getKeystoreFailed, err)
	}

	k.OperationalKeyIDs = append(k.OperationalKeyIDs, keyID)

	err = s.keystore.Save(k)
	if err != nil {
		return "", NewServiceError(saveKeystoreFailed, err)
	}

	return keyID, nil
}

// Sign signs a message.
func (s *service) Sign(keystoreID, keyID string, msg []byte) ([]byte, error) {
	kh, err := s.getKeyHandle(keystoreID, keyID)
	if err != nil {
		return nil, err
	}

	sig, err := s.crypto.Sign(msg, kh)
	if err != nil {
		return nil, NewServiceError(signMessageFailed, err)
	}

	return sig, nil
}

// Verify verifies a signature for the message.
func (s *service) Verify(keystoreID, keyID string, sig, msg []byte) error {
	kh, err := s.getKeyHandle(keystoreID, keyID)
	if err != nil {
		return err
	}

	pub, err := kh.(*keyset.Handle).Public()
	if err != nil {
		return NewServiceError(noPublicKeyFailure, err)
	}

	err = s.crypto.Verify(sig, msg, pub)
	if err != nil {
		return NewServiceError(verifySignatureFailed, err)
	}

	return nil
}

// Encrypt encrypts a message with additional authenticated data (AAD).
func (s *service) Encrypt(keystoreID, keyID string, msg, aad []byte) ([]byte, []byte, error) {
	kh, err := s.getKeyHandle(keystoreID, keyID)
	if err != nil {
		return nil, nil, err
	}

	cipher, nonce, err := s.crypto.Encrypt(msg, aad, kh)
	if err != nil {
		return nil, nil, NewServiceError(encryptMessageFailed, err)
	}

	return cipher, nonce, nil
}

// Decrypt decrypts a cipher with AAD and a nonce.
func (s *service) Decrypt(keystoreID, keyID string, cipher, aad, nonce []byte) ([]byte, error) {
	kh, err := s.getKeyHandle(keystoreID, keyID)
	if err != nil {
		return nil, err
	}

	plain, err := s.crypto.Decrypt(cipher, aad, nonce, kh)
	if err != nil {
		return nil, NewServiceError(decryptCipherFailed, err)
	}

	return plain, nil
}

// ComputeMAC computes message authentication code (MAC) for data.
func (s *service) ComputeMAC(keystoreID, keyID string, data []byte) ([]byte, error) {
	kh, err := s.getKeyHandle(keystoreID, keyID)
	if err != nil {
		return nil, err
	}

	mac, err := s.crypto.ComputeMAC(data, kh)
	if err != nil {
		return nil, NewServiceError(computeMACFailed, err)
	}

	return mac, nil
}

// VerifyMAC determines if the given mac is a correct message authentication code (MAC) for data.
func (s *service) VerifyMAC(keystoreID, keyID string, mac, data []byte) error {
	kh, err := s.getKeyHandle(keystoreID, keyID)
	if err != nil {
		return err
	}

	err = s.crypto.VerifyMAC(mac, data, kh)
	if err != nil {
		return NewServiceError(verifyMACFailed, err)
	}

	return nil
}

func (s *service) getKeyHandle(keystoreID, keyID string) (interface{}, error) {
	k, err := s.keystore.Get(keystoreID)
	if err != nil {
		return nil, NewServiceError(getKeystoreFailed, err)
	}

	if len(k.OperationalKeyIDs) == 0 {
		return nil, NewServiceError(noKeysFailure, nil)
	}

	found := false

	for _, id := range k.OperationalKeyIDs {
		if id == keyID {
			found = true

			break
		}
	}

	if !found {
		return nil, NewServiceError(invalidKeyFailure, nil)
	}

	kh, err := s.keyManager.Get(keyID)
	if err != nil {
		return nil, NewServiceError(getKeyFailed, err)
	}

	return kh, nil
}
