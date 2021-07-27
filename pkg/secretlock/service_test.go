/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package secretlock_test

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	mocksecretlock "github.com/hyperledger/aries-framework-go/pkg/mock/secretlock"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	ariesstorage "github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/stretchr/testify/require"

	lock "github.com/trustbloc/kms/pkg/secretlock"
)

const keyURI = "local-lock://test"

func TestNew(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		primaryKey := generateKey()

		mockPrimaryKeyLock := &mocksecretlock.MockSecretLock{
			ValDecrypt: string(primaryKey),
			ValEncrypt: string(primaryKey),
		}

		provider := &mockProvider{
			MockStorageProvider: mem.NewProvider(),
			MockSecretLock:      mockPrimaryKeyLock,
		}

		secretLock, err := lock.New(keyURI, provider, 0)

		require.NotNil(t, secretLock)
		require.NoError(t, err)
	})

	t.Run("DB error (get)", func(t *testing.T) {
		primaryKey := generateKey()

		storageProv := mockstorage.NewMockStoreProvider()
		storageProv.Store = &mockstorage.MockStore{ErrGet: errors.New("error")}

		mockPrimaryKeyLock := &mocksecretlock.MockSecretLock{
			ValDecrypt: string(primaryKey),
			ValEncrypt: string(primaryKey),
		}

		provider := &mockProvider{
			MockStorageProvider: storageProv,
			MockSecretLock:      mockPrimaryKeyLock,
		}

		secretLock, err := lock.New("test-key", provider, 0)

		require.EqualError(t, err, "get value for \"test-key\": error")
		require.Nil(t, secretLock)
	})

	t.Run("DB error (second get)", func(t *testing.T) {
		primaryKey := generateKey()

		var counter int

		storageProv := mockstorage.NewMockStoreProvider()
		storageProv.Custom = &mockStore{
			MockStore: &mockstorage.MockStore{
				Store: map[string]mockstorage.DBEntry{},
			},
			get: func(s string) ([]byte, error) {
				defer func() { counter++ }()

				if counter == 1 {
					return nil, nil
				}

				if counter == 2 {
					return nil, errors.New("error")
				}

				return nil, ariesstorage.ErrDataNotFound
			},
		}

		mockPrimaryKeyLock := &mocksecretlock.MockSecretLock{
			ValDecrypt: string(primaryKey),
			ValEncrypt: string(primaryKey),
		}

		provider := &mockProvider{
			MockStorageProvider: storageProv,
			MockSecretLock:      mockPrimaryKeyLock,
		}

		secretLock, err := lock.New("test-key", provider, 1)

		require.EqualError(t, err, "get value for \"test-key\": error")
		require.Nil(t, secretLock)
	})

	t.Run("Encrypt error (get)", func(t *testing.T) {
		primaryKey := generateKey()

		mockPrimaryKeyLock := &mocksecretlock.MockSecretLock{
			ValDecrypt: string(primaryKey),
			ErrEncrypt: errors.New("error"),
		}

		provider := &mockProvider{
			MockStorageProvider: mem.NewProvider(),
			MockSecretLock:      mockPrimaryKeyLock,
		}

		secretLock, err := lock.New("test-key", provider, 0)

		require.EqualError(t, err, "init value for \"test-key\": encrypt primary key: error")
		require.Nil(t, secretLock)
	})

	t.Run("DB error (put)", func(t *testing.T) {
		primaryKey := generateKey()

		storageProv := mockstorage.NewMockStoreProvider()
		storageProv.Store = &mockstorage.MockStore{ErrPut: errors.New("error")}

		mockPrimaryKeyLock := &mocksecretlock.MockSecretLock{
			ValDecrypt: string(primaryKey),
			ValEncrypt: string(primaryKey),
		}

		provider := &mockProvider{
			MockStorageProvider: storageProv,
			MockSecretLock:      mockPrimaryKeyLock,
		}

		secretLock, err := lock.New("test-key", provider, 0)

		require.EqualError(t, err, "put value for \"test-key\": error")
		require.Nil(t, secretLock)
	})

	t.Run("Error: opening master key store", func(t *testing.T) {
		storageProv := mockstorage.NewMockStoreProvider()
		storageProv.ErrOpenStoreHandle = errors.New("open store error")

		provider := &mockProvider{
			MockStorageProvider: storageProv,
			MockSecretLock:      &mocksecretlock.MockSecretLock{},
		}

		secretLock, err := lock.New(keyURI, provider, 0)

		require.Nil(t, secretLock)
		require.Error(t, err)
	})

	t.Run("Error: getting from master key store", func(t *testing.T) {
		storageProv := mockstorage.NewMockStoreProvider()
		storageProv.Store.ErrGet = errors.New("store get error")

		provider := &mockProvider{
			MockStorageProvider: storageProv,
			MockSecretLock:      &mocksecretlock.MockSecretLock{},
		}

		secretLock, err := lock.New(keyURI, provider, 0)

		require.Nil(t, secretLock)
		require.Error(t, err)
	})

	t.Run("Error: encrypting new primary key", func(t *testing.T) {
		mockPrimaryKeyLock := &mocksecretlock.MockSecretLock{}
		mockPrimaryKeyLock.ErrEncrypt = errors.New("encrypt error")

		provider := &mockProvider{
			MockStorageProvider: mockstorage.NewMockStoreProvider(),
			MockSecretLock:      mockPrimaryKeyLock,
		}

		secretLock, err := lock.New(keyURI, provider, 0)

		require.Nil(t, secretLock)
		require.Error(t, err)
	})

	t.Run("Error: saving into primary key store", func(t *testing.T) {
		storageProv := mockstorage.NewMockStoreProvider()
		storageProv.Store.ErrPut = errors.New("store put error")

		provider := &mockProvider{
			MockStorageProvider: storageProv,
			MockSecretLock:      &mocksecretlock.MockSecretLock{},
		}

		secretLock, err := lock.New(keyURI, provider, 0)

		require.Nil(t, secretLock)
		require.Error(t, err)
	})

	t.Run("Error: create new local secret lock service", func(t *testing.T) {
		provider := &mockProvider{
			MockStorageProvider: mockstorage.NewMockStoreProvider(),
			MockSecretLock:      &mocksecretlock.MockSecretLock{},
		}

		secretLock, err := lock.New(keyURI, provider, 0)

		require.Nil(t, secretLock)
		require.Error(t, err)
	})
}

func generateKey() []byte {
	buf := make([]byte, sha256.Size)

	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}

	return buf
}

type mockProvider struct {
	MockStorageProvider ariesstorage.Provider
	MockSecretLock      *mocksecretlock.MockSecretLock
}

func (p *mockProvider) StorageProvider() ariesstorage.Provider {
	return p.MockStorageProvider
}

func (p *mockProvider) SecretLock() secretlock.Service {
	return p.MockSecretLock
}

type mockStore struct {
	*mockstorage.MockStore
	get func(string) ([]byte, error)
}

func (s *mockStore) Get(k string) ([]byte, error) {
	return s.get(k)
}
