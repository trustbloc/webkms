/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package secretlock

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/local"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

const (
	primaryKeyStoreName = "primarykey"
	localLockPrefix     = "local-lock://"
	keySize             = sha256.Size
)

// Provider contains dependencies for the secret lock service.
type Provider interface {
	StorageProvider() storage.Provider
	SecretLock() secretlock.Service
}

// New returns a new secret lock service instance.
func New(keyURI string, provider Provider) (secretlock.Service, error) {
	r, err := primaryKeyReader(provider.StorageProvider(), provider.SecretLock(), keyURI)
	if err != nil {
		return nil, err
	}

	secretLock, err := local.NewService(r, provider.SecretLock())
	if err != nil {
		return nil, err
	}

	return secretLock, nil
}

func primaryKeyReader(storageProvider storage.Provider, secretLock secretlock.Service,
	keyURI string) (*bytes.Reader, error) {
	primaryKeyStore, err := storageProvider.OpenStore(primaryKeyStoreName)
	if err != nil {
		return nil, err
	}

	primaryKey, err := primaryKeyStore.Get(keyEntryInDB(keyURI))
	if err != nil {
		if errors.Is(err, storage.ErrDataNotFound) {
			primaryKey, err = newPrimaryKey(primaryKeyStore, secretLock, keyURI)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	return bytes.NewReader(primaryKey), nil
}

func newPrimaryKey(store storage.Store, secLock secretlock.Service, keyURI string) ([]byte, error) {
	primaryKeyContent, err := randomBytes(keySize)
	if err != nil {
		return nil, err
	}

	primaryKeyEnc, err := secLock.Encrypt(keyURI, &secretlock.EncryptRequest{
		Plaintext: string(primaryKeyContent),
	})
	if err != nil {
		return nil, err
	}

	primaryKey := []byte(primaryKeyEnc.Ciphertext)

	err = store.Put(keyEntryInDB(keyURI), primaryKey)
	if err != nil {
		return nil, err
	}

	return primaryKey, nil
}

func keyEntryInDB(keyURI string) string {
	return strings.ReplaceAll(keyURI, localLockPrefix, "")
}

func randomBytes(size uint32) ([]byte, error) {
	buf := make([]byte, size)

	_, err := rand.Read(buf)
	if err != nil {
		return nil, err
	}

	return buf, nil
}
