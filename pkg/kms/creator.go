/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"crypto/sha256"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/local/masterlock/hkdf"
	"github.com/hyperledger/aries-framework-go/pkg/storage"

	"github.com/trustbloc/hub-kms/pkg/keystore"
)

const (
	masterKeyURI         = "local-lock://%s"
	keystoreIDQueryParam = "keystoreID"
	secretHeader         = "Hub-Kms-Secret" //nolint:gosec // not hardcoded credentials
)

// ServiceCreator is a function that creates KMS Service.
type ServiceCreator func(req *http.Request) (Service, error)

// Config defines configuration for ServiceCreator.
type Config struct {
	KeystoreService               keystore.Service
	CryptoService                 crypto.Crypto
	OperationalKMSStorageResolver func(keystoreID string) (storage.Provider, error)
}

// NewServiceCreator returns func to create KMS Service backed by LocalKMS and passphrase-based secret lock.
func NewServiceCreator(c *Config) ServiceCreator {
	return func(req *http.Request) (Service, error) {
		keystoreID := mux.Vars(req)[keystoreIDQueryParam]
		keyURI := fmt.Sprintf(masterKeyURI, keystoreID)

		// TODO(#22): Replace with split secret shares. Consider to use "Hub-Kms-Secret-A" and "Hub-Kms-Secret-B-Path"
		// headers to pass a content of secret A and a location to secret B accordingly.
		secret := req.Header.Get(secretHeader)

		secLock, err := hkdf.NewMasterLock(secret, sha256.New, nil)
		if err != nil {
			return nil, err
		}

		kmsStorageProvider, err := c.OperationalKMSStorageResolver(keystoreID)
		if err != nil {
			return nil, err
		}

		keyManager, err := NewLocalKMS(keyURI, kmsStorageProvider, secLock)
		if err != nil {
			return nil, err
		}

		provider := kmsServiceProvider{
			keystoreService: c.KeystoreService,
			keyManager:      keyManager,
			crypto:          c.CryptoService,
		}

		return NewService(provider), nil
	}
}

type kmsServiceProvider struct {
	keystoreService keystore.Service
	keyManager      kms.KeyManager
	crypto          crypto.Crypto
}

func (k kmsServiceProvider) KeystoreService() keystore.Service {
	return k.keystoreService
}

func (k kmsServiceProvider) KeyManager() kms.KeyManager {
	return k.keyManager
}

func (k kmsServiceProvider) Crypto() crypto.Crypto {
	return k.crypto
}
