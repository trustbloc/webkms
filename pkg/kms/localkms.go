/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/local"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

const (
	masterKeyStoreName = "masterkey"
	masterKeyDBKeyName = masterKeyStoreName
	keySize            = sha256.Size
)

type kmsProvider struct {
	storageProvider storage.Provider
	secretLock      secretlock.Service
}

func (k kmsProvider) StorageProvider() storage.Provider {
	return k.storageProvider
}

func (k kmsProvider) SecretLock() secretlock.Service {
	return k.secretLock
}

// NewLocalKMS returns a new LocalKMS instance.
func NewLocalKMS(keyURI string, storageProv storage.Provider, lock secretlock.Service) (*localkms.LocalKMS, error) {
	masterKeyReader, err := prepareMasterKeyReader(storageProv, lock, keyURI)
	if err != nil {
		return nil, err
	}

	secretLockService, err := local.NewService(masterKeyReader, lock)
	if err != nil {
		return nil, err
	}

	kmsProv := kmsProvider{
		storageProvider: storageProv,
		secretLock:      secretLockService,
	}

	return localkms.New(keyURI, kmsProv)
}

func prepareMasterKeyReader(storageProvider storage.Provider, secLock secretlock.Service,
	keyURI string) (*bytes.Reader, error) {
	masterKeyStore, err := storageProvider.OpenStore(masterKeyStoreName)
	if err != nil {
		return nil, err
	}

	masterKey, err := masterKeyStore.Get(masterKeyDBKeyName)
	if err != nil {
		if errors.Is(err, storage.ErrDataNotFound) {
			masterKey, err = prepareNewMasterKey(masterKeyStore, secLock, keyURI)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	return bytes.NewReader(masterKey), nil
}

func prepareNewMasterKey(masterKeyStore storage.Store, secLock secretlock.Service, keyURI string) ([]byte, error) {
	masterKeyContent := randomBytes(keySize)

	masterKeyEnc, err := secLock.Encrypt(keyURI, &secretlock.EncryptRequest{
		Plaintext: string(masterKeyContent),
	})
	if err != nil {
		return nil, err
	}

	masterKey := []byte(masterKeyEnc.Ciphertext)

	err = masterKeyStore.Put(masterKeyDBKeyName, masterKey)
	if err != nil {
		return nil, err
	}

	return masterKey, nil
}

func randomBytes(size uint32) []byte {
	buf := make([]byte, size)

	_, err := rand.Read(buf)
	if err != nil {
		panic(err) // out of randomness, should never happen
	}

	return buf
}
