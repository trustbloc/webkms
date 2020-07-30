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
	t.Run("Success", func(t *testing.T) {
		repo, err := keystore.NewRepository(mockstore.NewMockStoreProvider())

		require.NotNil(t, repo)
		require.NoError(t, err)
	})

	t.Run("Success: ignore duplicate store error", func(t *testing.T) {
		provider := mockstore.NewMockStoreProvider()
		provider.ErrCreateStore = storage.ErrDuplicateStore

		repo, err := keystore.NewRepository(provider)

		require.NotNil(t, repo)
		require.NoError(t, err)
	})

	t.Run("Error: create store", func(t *testing.T) {
		provider := mockstore.NewMockStoreProvider()
		provider.ErrCreateStore = errors.New("create store error")

		repo, err := keystore.NewRepository(provider)

		require.Nil(t, repo)
		require.Error(t, err)
	})

	t.Run("Error: open store", func(t *testing.T) {
		provider := mockstore.NewMockStoreProvider()
		provider.ErrOpenStoreHandle = errors.New("open store error")

		repo, err := keystore.NewRepository(provider)

		require.Nil(t, repo)
		require.Error(t, err)
	})
}

func TestGet(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		keystorePut := keystore.Keystore{ID: testKeystoreID}
		bytes, err := json.Marshal(keystorePut)
		require.NoError(t, err)

		provider := mockstore.NewMockStoreProvider()
		err = provider.Store.Put(testKeystoreID, bytes)
		require.NoError(t, err)

		repo, err := keystore.NewRepository(provider)
		require.NoError(t, err)

		keystoreGet, err := repo.Get(testKeystoreID)
		require.NoError(t, err)
		require.Equal(t, keystorePut.ID, keystoreGet.ID)
	})

	t.Run("Error: store get", func(t *testing.T) {
		provider := mockstore.NewMockStoreProvider()
		provider.Store.ErrGet = errors.New("get error")

		repo, err := keystore.NewRepository(provider)
		require.NoError(t, err)

		k, err := repo.Get(testKeystoreID)
		require.Nil(t, k)
		require.Error(t, err)
	})
}

func TestSave(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider := mockstore.NewMockStoreProvider()
		repo, err := keystore.NewRepository(provider)
		require.NoError(t, err)

		keystorePut := &keystore.Keystore{ID: testKeystoreID}
		err = repo.Save(keystorePut)
		require.NoError(t, err)

		bytes, err := provider.Store.Get(testKeystoreID)

		var keystoreGet keystore.Keystore
		err = json.Unmarshal(bytes, &keystoreGet)
		require.NoError(t, err)
		require.Equal(t, keystorePut.ID, keystoreGet.ID)
	})

	t.Run("Error: store put", func(t *testing.T) {
		provider := mockstore.NewMockStoreProvider()
		provider.Store.ErrPut = errors.New("put error")

		repo, err := keystore.NewRepository(provider)
		require.NoError(t, err)

		err = repo.Save(&keystore.Keystore{ID: testKeystoreID})
		require.Error(t, err)
	})
}
