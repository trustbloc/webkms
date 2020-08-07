/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"errors"
	"fmt"

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

// Service provides kms/crypto functions on keys.
type Service interface {
	CreateKey(keystoreID string, kt kms.KeyType) (string, error)
	Sign(keystoreID, keyID string, msg []byte) ([]byte, error)
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

// Sign signs a message using the key identified by keyID.
func (s *service) Sign(keystoreID, keyID string, msg []byte) ([]byte, error) {
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

	return s.crypto.Sign(msg, kh)
}
