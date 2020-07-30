/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/kms"

	"github.com/trustbloc/hub-kms/pkg/keystore"
)

const (
	createKeyErr    = "create key: %w"
	getKeystoreErr  = "get keystore: %w"
	saveKeystoreErr = "save keystore: %w"
)

// Service provides kms/crypto functions on keys.
type Service interface {
	CreateKey(keystoreID string, kt kms.KeyType) (string, error)
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

func NewService(provider Provider) Service {
	return &service{
		keystore:   provider.Keystore(),
		keyManager: provider.KMS(),
		crypto:     provider.Crypto(),
	}
}

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
