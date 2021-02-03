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

	mocksecretlock "github.com/hyperledger/aries-framework-go/pkg/mock/secretlock"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	ariesstorage "github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/stretchr/testify/require"

	lock "github.com/trustbloc/kms/pkg/secretlock"
)

const (
	keyURI       = "local-lock://test"
	keyEntryInDB = "test"
)

func TestNew(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		primaryKey := generateKey()

		storageProv := mockstorage.NewMockStoreProvider()
		storageProv.Store.Store[keyEntryInDB] = primaryKey

		mockPrimaryKeyLock := &mocksecretlock.MockSecretLock{
			ValDecrypt: string(primaryKey),
		}

		provider := &mockProvider{
			MockStorageProvider: storageProv,
			MockSecretLock:      mockPrimaryKeyLock,
		}

		secretLock, err := lock.New(keyURI, provider)

		require.NotNil(t, secretLock)
		require.NoError(t, err)
	})

	t.Run("Error: opening master key store", func(t *testing.T) {
		storageProv := mockstorage.NewMockStoreProvider()
		storageProv.ErrOpenStoreHandle = errors.New("open store error")

		provider := &mockProvider{
			MockStorageProvider: storageProv,
			MockSecretLock:      &mocksecretlock.MockSecretLock{},
		}

		secretLock, err := lock.New(keyURI, provider)

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

		secretLock, err := lock.New(keyURI, provider)

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

		secretLock, err := lock.New(keyURI, provider)

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

		secretLock, err := lock.New(keyURI, provider)

		require.Nil(t, secretLock)
		require.Error(t, err)
	})

	t.Run("Error: create new local secret lock service", func(t *testing.T) {
		provider := &mockProvider{
			MockStorageProvider: mockstorage.NewMockStoreProvider(),
			MockSecretLock:      &mocksecretlock.MockSecretLock{},
		}

		secretLock, err := lock.New(keyURI, provider)

		require.Nil(t, secretLock)
		require.Error(t, err)
	})
}

func generateKey() []byte {
	buf := make([]byte, sha256.Size)

	_, err := rand.Read(buf)
	if err != nil {
		panic(err)
	}

	return buf
}

type mockProvider struct {
	MockStorageProvider *mockstorage.MockStoreProvider
	MockSecretLock      *mocksecretlock.MockSecretLock
}

func (p *mockProvider) StorageProvider() ariesstorage.Provider {
	return p.MockStorageProvider
}

func (p *mockProvider) SecretLock() secretlock.Service {
	return p.MockSecretLock
}
