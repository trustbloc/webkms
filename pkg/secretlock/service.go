/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package secretlock

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

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

// New returns a new secret lock service instance.
func New(keyURI string, provider Provider, timeout uint64) (secretlock.Service, error) {
	r, err := primaryKeyReader(provider.StorageProvider(), provider.SecretLock(), keyURI, timeout)
	if err != nil {
		return nil, err
	}

	secretLock, err := local.NewService(r, provider.SecretLock())
	if err != nil {
		return nil, fmt.Errorf("new local secretlock: %w", err)
	}

	return secretLock, nil
}

var cache sync.Map //nolint:gochecknoglobals // cache stores primary key per keystore

func primaryKeyReader(storageProvider storage.Provider, secretLock secretlock.Service,
	keyURI string, timeout uint64) (*bytes.Reader, error) {
	val, ok := cache.Load(keyEntryInDB(keyURI))
	if ok {
		return bytes.NewReader(val.([]byte)), nil
	}

	primaryKeyStore, err := storageProvider.OpenStore(primaryKeyStoreName)
	if err != nil {
		return nil, fmt.Errorf("open primary key store: %w", err)
	}

	// TODO needs to be refactored with a better solution

	var primaryKey []byte
	err = getOrInit(primaryKeyStore, keyEntryInDB(keyURI), &primaryKey, func() (interface{}, error) {
		return newPrimaryKey(secretLock, keyURI)
	}, timeout)

	if err != nil {
		return nil, err
	}

	cache.Store(keyEntryInDB(keyURI), primaryKey)

	return bytes.NewReader(primaryKey), nil
}

//nolint:gocyclo // ignore
func getOrInit(cfg storage.Store, key string, v interface{}, initFn func() (interface{}, error), timeout uint64) error {
	src, err := cfg.Get(key)
	if err != nil && !errors.Is(err, storage.ErrDataNotFound) {
		return fmt.Errorf("get value for %q: %w", key, err)
	}

	if err == nil {
		time.Sleep(time.Second * time.Duration(timeout))

		var src2 []byte

		src2, err = cfg.Get(key)
		if err != nil && errors.Is(err, storage.ErrDataNotFound) {
			return getOrInit(cfg, key, v, initFn, timeout)
		}

		if err != nil {
			return fmt.Errorf("get value for %q: %w", key, err)
		}

		if reflect.DeepEqual(src, src2) {
			return json.Unmarshal(src, v)
		}

		return getOrInit(cfg, key, v, initFn, timeout)
	}

	val, err := initFn()
	if err != nil {
		return fmt.Errorf("init value for %q: %w", key, err)
	}

	src, err = json.Marshal(val)
	if err != nil {
		return fmt.Errorf("marshal value for %q: %w", key, err)
	}

	if err = cfg.Put(key, src); err != nil {
		return fmt.Errorf("put value for %q: %w", key, err)
	}

	return getOrInit(cfg, key, v, initFn, timeout)
}

func newPrimaryKey(secLock secretlock.Service, keyURI string) ([]byte, error) {
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

	return []byte(primaryKeyEnc.Ciphertext), nil
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
