/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"errors"
	"fmt"
	"strings"

	"github.com/google/tink/go/keyset"

	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/kms"

	"github.com/trustbloc/hub-kms/pkg/keystore"
)

const (
	createKeyErr    = "create key: %w"
	noKeysErr       = "no keys defined"
	invalidKeyIDErr = "invalid key ID"
	getKeyErr       = "get key: %w"
	getKeystoreErr  = "get keystore: %w"
	saveKeystoreErr = "save keystore: %w"
)

var ErrInvalidSignature = errors.New("invalid signature")

// Service provides kms/crypto functions on keys.
type Service interface {
	CreateKey(keystoreID string, kt kms.KeyType) (string, error)
	Sign(keystoreID, keyID string, msg []byte) ([]byte, error)
	Verify(keystoreID, keyID string, sig, msg []byte) error
	Encrypt(keystoreID, keyID string, msg, aad []byte) ([]byte, []byte, error)
	Decrypt(keystoreID, keyID string, cipher, aad, nonce []byte) ([]byte, error)
	ComputeMAC(keystoreID, keyID string, data []byte) ([]byte, error)
	VerifyMAC(keystoreID, keyID string, mac, data []byte) error
}

// Provider contains dependencies for the KMS service constructor.
type Provider interface {
	Keystore() keystore.Repository
	KMS() kms.KeyManager
	Crypto() crypto.Crypto
}

type service struct {
	keystore   keystore.Repository
	keyManager kms.KeyManager
	crypto     crypto.Crypto
}

// NewService returns a new Service instance with provided dependencies.
func NewService(provider Provider) Service {
	return &service{
		keystore:   provider.Keystore(),
		keyManager: provider.KMS(),
		crypto:     provider.Crypto(),
	}
}

// CreateKey creates a new key and associates it with a keystore.
func (s *service) CreateKey(keystoreID string, kt kms.KeyType) (string, error) {
	keyID, _, err := s.keyManager.Create(kt)
	if err != nil {
		return "", fmt.Errorf(createKeyErr, err)
	}

	k, err := s.keystore.Get(keystoreID)
	if err != nil {
		return "", fmt.Errorf(getKeystoreErr, err)
	}

	k.KeyIDs = append(k.KeyIDs, keyID)

	err = s.keystore.Save(k)
	if err != nil {
		return "", fmt.Errorf(saveKeystoreErr, err)
	}

	return keyID, nil
}

// Sign signs a message.
func (s *service) Sign(keystoreID, keyID string, msg []byte) ([]byte, error) {
	kh, err := s.getKeyHandle(keystoreID, keyID)
	if err != nil {
		return nil, err
	}

	return s.crypto.Sign(msg, kh)
}

// Verify verifies a signature for the given message.
func (s *service) Verify(keystoreID, keyID string, sig, msg []byte) error {
	kh, err := s.getKeyHandle(keystoreID, keyID)
	if err != nil {
		return err
	}

	pub, err := kh.(*keyset.Handle).Public()
	if err != nil {
		return err
	}

	err = s.crypto.Verify(sig, msg, pub)
	if err != nil && strings.Contains(err.Error(), "verify msg:") {
		return ErrInvalidSignature
	}

	return err
}

// Encrypt encrypts a message with aad.
func (s *service) Encrypt(keystoreID, keyID string, msg, aad []byte) ([]byte, []byte, error) {
	kh, err := s.getKeyHandle(keystoreID, keyID)
	if err != nil {
		return nil, nil, err
	}

	return s.crypto.Encrypt(msg, aad, kh)
}

// Decrypt decrypts a cipher with aad and given nonce.
func (s *service) Decrypt(keystoreID, keyID string, cipher, aad, nonce []byte) ([]byte, error) {
	kh, err := s.getKeyHandle(keystoreID, keyID)
	if err != nil {
		return nil, err
	}

	return s.crypto.Decrypt(cipher, aad, nonce, kh)
}

// ComputeMAC computes message authentication code (MAC) for data.
func (s *service) ComputeMAC(keystoreID, keyID string, data []byte) ([]byte, error) {
	kh, err := s.getKeyHandle(keystoreID, keyID)
	if err != nil {
		return nil, err
	}

	return s.crypto.ComputeMAC(data, kh)
}

// VerifyMAC determines if mac is a correct authentication code (MAC) for data.
func (s *service) VerifyMAC(keystoreID, keyID string, mac, data []byte) error {
	kh, err := s.getKeyHandle(keystoreID, keyID)
	if err != nil {
		return err
	}

	return s.crypto.VerifyMAC(mac, data, kh)
}

func (s *service) getKeyHandle(keystoreID, keyID string) (interface{}, error) {
	k, err := s.keystore.Get(keystoreID)
	if err != nil {
		return nil, fmt.Errorf(getKeystoreErr, err)
	}

	if len(k.KeyIDs) == 0 {
		return nil, errors.New(noKeysErr)
	}

	found := false
	for _, id := range k.KeyIDs {
		if id == keyID {
			found = true
			break
		}
	}

	if !found {
		return nil, errors.New(invalidKeyIDErr)
	}

	kh, err := s.keyManager.Get(keyID)
	if err != nil {
		return nil, fmt.Errorf(getKeyErr, err)
	}

	return kh, nil
}
