/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package keystore_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/storage"
	"github.com/trustbloc/edge-core/pkg/storage/mockstore"

	"github.com/trustbloc/hub-kms/pkg/keystore"
)

const (
	testKeystoreID = "keystoreID"
)

func TestNewRepository(t *testing.T) {
	repo := keystore.NewRepository(mockstore.NewMockStoreProvider())
	require.NotNil(t, repo)
}

func TestGet(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider := mockstore.NewMockStoreProvider()
		provider.Store.Store[testKeystoreID] = keystoreBytes(t)

		repo := keystore.NewRepository(provider)
		k, err := repo.Get(testKeystoreID)

		require.NoError(t, err)
		require.NotNil(t, k)
		require.Equal(t, testKeystoreID, k.ID)
	})

	t.Run("Success: ignore duplicate store error", func(t *testing.T) {
		provider := mockstore.NewMockStoreProvider()
		provider.ErrCreateStore = storage.ErrDuplicateStore
		provider.Store.Store[testKeystoreID] = keystoreBytes(t)

		repo := keystore.NewRepository(provider)
		k, err := repo.Get(testKeystoreID)

		require.NoError(t, err)
		require.NotNil(t, k)
		require.Equal(t, testKeystoreID, k.ID)
	})

	t.Run("Error: open store", func(t *testing.T) {
		provider := mockstore.NewMockStoreProvider()
		provider.ErrOpenStoreHandle = errors.New("open store error")
		provider.Store.Store[testKeystoreID] = keystoreBytes(t)

		repo := keystore.NewRepository(provider)
		k, err := repo.Get(testKeystoreID)

		require.Error(t, err)
		require.Nil(t, k)
	})

	t.Run("Error: store get", func(t *testing.T) {
		provider := mockstore.NewMockStoreProvider()
		provider.Store.ErrGet = errors.New("get error")
		provider.Store.Store[testKeystoreID] = keystoreBytes(t)

		repo := keystore.NewRepository(provider)
		k, err := repo.Get(testKeystoreID)

		require.Error(t, err)
		require.Nil(t, k)
	})
}

func TestSave(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider := mockstore.NewMockStoreProvider()
		repo := keystore.NewRepository(provider)

		err := repo.Save(&keystore.Keystore{ID: testKeystoreID})

		require.NoError(t, err)
		assertStoredKeystore(t, provider.Store)
	})

	t.Run("Success: ignore duplicate store error", func(t *testing.T) {
		provider := mockstore.NewMockStoreProvider()
		provider.ErrCreateStore = storage.ErrDuplicateStore
		repo := keystore.NewRepository(provider)

		err := repo.Save(&keystore.Keystore{ID: testKeystoreID})

		require.NoError(t, err)
		assertStoredKeystore(t, provider.Store)
	})

	t.Run("Error: open store", func(t *testing.T) {
		provider := mockstore.NewMockStoreProvider()
		provider.ErrOpenStoreHandle = errors.New("open store error")
		repo := keystore.NewRepository(provider)

		err := repo.Save(&keystore.Keystore{ID: testKeystoreID})

		require.Error(t, err)
	})

	t.Run("Error: store put", func(t *testing.T) {
		provider := mockstore.NewMockStoreProvider()
		provider.Store.ErrPut = errors.New("put error")

		repo := keystore.NewRepository(provider)
		err := repo.Save(&keystore.Keystore{ID: testKeystoreID})

		require.Error(t, err)
	})
}

func keystoreBytes(t *testing.T) []byte {
	t.Helper()

	k := keystore.Keystore{ID: testKeystoreID}
	b, err := json.Marshal(k)
	require.NoError(t, err)

	return b
}

func assertStoredKeystore(t *testing.T, store *mockstore.MockStore) {
	t.Helper()

	b := store.Store[testKeystoreID]
	require.NotNil(t, b)

	var k keystore.Keystore
	err := json.Unmarshal(b, &k)

	require.NoError(t, err)
	require.Equal(t, testKeystoreID, k.ID)
}
