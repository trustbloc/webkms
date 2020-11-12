/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/local/masterlock/hkdf"
	"github.com/hyperledger/aries-framework-go/pkg/storage"

	"github.com/trustbloc/hub-kms/pkg/keystore"
)

const (
	masterKeyURI         = "local-lock://%s"
	keystoreIDQueryParam = "keystoreID"
)

// ServiceCreator is a function that creates KMS Service.
type ServiceCreator func(req *http.Request) (Service, error)

// NewServiceCreator returns func to create KMS Service backed by LocalKMS and passphrase-based secret lock.
func NewServiceCreator(keystoreService keystore.Service, kmsStorageProvider storage.Provider) ServiceCreator {
	return func(req *http.Request) (Service, error) {
		keystoreID := mux.Vars(req)[keystoreIDQueryParam]
		keyURI := fmt.Sprintf(masterKeyURI, keystoreID)

		b, err := cloneRequestBody(req)
		if err != nil {
			return nil, err
		}

		p := struct {
			Passphrase string `json:"passphrase"`
		}{}

		err = json.NewDecoder(b).Decode(&p)
		if err != nil {
			return nil, err
		}

		secLock, err := hkdf.NewMasterLock(p.Passphrase, sha256.New, nil)
		if err != nil {
			return nil, err
		}

		keyManager, err := NewLocalKMS(keyURI, kmsStorageProvider, secLock)
		if err != nil {
			return nil, err
		}

		c, err := tinkcrypto.New()
		if err != nil {
			return nil, err
		}

		provider := kmsServiceProvider{
			keystoreService:       keystoreService,
			operationalKeyManager: keyManager,
			crypto:                c,
		}

		return NewService(provider), nil
	}
}

type kmsServiceProvider struct {
	keystoreService       keystore.Service
	operationalKeyManager kms.KeyManager
	crypto                crypto.Crypto
}

func (k kmsServiceProvider) KeystoreService() keystore.Service {
	return k.keystoreService
}

func (k kmsServiceProvider) OperationalKeyManager() kms.KeyManager {
	return k.operationalKeyManager
}

func (k kmsServiceProvider) Crypto() crypto.Crypto {
	return k.crypto
}

func cloneRequestBody(req *http.Request) (io.ReadCloser, error) {
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}

	req.Body = ioutil.NopCloser(bytes.NewReader(body))

	return ioutil.NopCloser(bytes.NewReader(body)), nil
}
