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
	"fmt"
	"strings"
	"sync"

	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/local"
	"github.com/hyperledger/aries-framework-go/spi/storage"
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

// TODO: think about how it can be improved for multi instances.
var glock sync.Mutex //nolint:gochecknoglobals // global lock for secretlock.Service

// New returns a new secret lock service instance.
func New(keyURI string, provider Provider) (secretlock.Service, error) {
	glock.Lock()
	defer glock.Unlock()

	r, err := primaryKeyReader(provider.StorageProvider(), provider.SecretLock(), keyURI)
	if err != nil {
		return nil, err
	}

	secretLock, err := local.NewService(r, provider.SecretLock())
	if err != nil {
		return nil, fmt.Errorf("new local secretlock: %w", err)
	}

	return secretLock, nil
}

func primaryKeyReader(storageProvider storage.Provider, secretLock secretlock.Service,
	keyURI string) (*bytes.Reader, error) {
	primaryKeyStore, err := storageProvider.OpenStore(primaryKeyStoreName)
	if err != nil {
		return nil, fmt.Errorf("open primary key store: %w", err)
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
		return nil, fmt.Errorf("encrypt primary key: %w", err)
	}

	primaryKey := []byte(primaryKeyEnc.Ciphertext)

	err = store.Put(keyEntryInDB(keyURI), primaryKey)
	if err != nil {
		return nil, fmt.Errorf("save primary key: %w", err)
	}

	return primaryKey, nil
}

func keyEntryInDB(keyURI string) string {
	return strings.ReplaceAll(keyURI, localLockPrefix, "")
}

func randomBytes(size uint32) ([]byte, error) {
	buf := make([]byte, size)

	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("random bytes: %w", err)
	}

	return buf, nil
}
