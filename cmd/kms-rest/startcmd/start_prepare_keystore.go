/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"fmt"

	arieskms "github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	ariesstorage "github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/trustbloc/edge-core/pkg/storage"

	"github.com/trustbloc/hub-kms/pkg/keystore"
)

const (
	keystorePrimaryKeyURI = "local-lock://keystorekms"
)

func prepareKeystoreService(keystoreStorage storage.Provider, localKMSStorage, primaryKeyStorage ariesstorage.Provider,
	secretLockKeyPath string) (keystore.Service, error) {
	secretLock, err := preparePrimaryKeyLock(primaryKeyStorage, secretLockKeyPath)
	if err != nil {
		return nil, err
	}

	kmsProvider := &kmsProvider{
		storageProvider: localKMSStorage,
		secretLock:      secretLock,
	}

	kmsCreator := func(provider arieskms.Provider) (arieskms.KeyManager, error) {
		k, kerr := localkms.New(keystorePrimaryKeyURI, provider)
		if kerr != nil {
			return nil, fmt.Errorf("failed to create localkms: %w", kerr)
		}

		return k, nil
	}

	keystoreServiceProv := keystoreServiceProvider{
		storageProvider: keystoreStorage,
		kmsProvider:     kmsProvider,
		kmsCreator:      kmsCreator,
	}

	keystoreService, err := keystore.NewService(keystoreServiceProv)
	if err != nil {
		return nil, err
	}

	return keystoreService, nil
}

type kmsProvider struct {
	storageProvider ariesstorage.Provider
	secretLock      secretlock.Service
}

func (k kmsProvider) StorageProvider() ariesstorage.Provider {
	return k.storageProvider
}

func (k kmsProvider) SecretLock() secretlock.Service {
	return k.secretLock
}

type keystoreServiceProvider struct {
	storageProvider storage.Provider
	kmsProvider     arieskms.Provider
	kmsCreator      arieskms.Creator
}

func (p keystoreServiceProvider) StorageProvider() storage.Provider {
	return p.storageProvider
}

func (p keystoreServiceProvider) KMSProvider() arieskms.Provider {
	return p.kmsProvider
}

func (p keystoreServiceProvider) KMSCreator() arieskms.Creator {
	return p.kmsCreator
}
