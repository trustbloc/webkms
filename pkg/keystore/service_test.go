/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package keystore_test

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	arieskms "github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/storage"

	mock "github.com/trustbloc/hub-kms/pkg/internal/mock/keystore"
	"github.com/trustbloc/hub-kms/pkg/keystore"
)

const (
	testController = "controller"
	testKeystoreID = "keystoreID"
	testKeyID      = "keyID"
	testKeyType    = arieskms.ED25519Type
)

func TestNewService(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		srv, err := keystore.NewService(mock.NewMockProvider())

		require.NotNil(t, srv)
		require.NoError(t, err)
	})

	t.Run("Success: duplicate store during creation", func(t *testing.T) {
		provider := mock.NewMockProvider()
		provider.MockStorageProvider.ErrCreateStore = storage.ErrDuplicateStore

		srv, err := keystore.NewService(mock.NewMockProvider())

		require.NotNil(t, srv)
		require.NoError(t, err)
	})

	t.Run("Error: create store error other than ErrDuplicateStore", func(t *testing.T) {
		provider := mock.NewMockProvider()
		provider.MockStorageProvider.ErrCreateStore = errors.New("create store error")

		srv, err := keystore.NewService(provider)

		require.Nil(t, srv)
		require.Error(t, err)
	})

	t.Run("Error: open store", func(t *testing.T) {
		provider := mock.NewMockProvider()
		provider.MockStorageProvider.ErrOpenStoreHandle = errors.New("open store error")

		srv, err := keystore.NewService(provider)

		require.Nil(t, srv)
		require.Error(t, err)
	})

	t.Run("Error: key manager creator", func(t *testing.T) {
		provider := mock.NewMockProvider()
		provider.KeyManagerCreatorError = errors.New("key manager creator error")

		srv, err := keystore.NewService(provider)

		require.Nil(t, srv)
		require.Error(t, err)
	})
}

func TestCreate(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider := mock.NewMockProvider()
		provider.MockKeyManager.CreateKeyID = testKeyID

		srv, err := keystore.NewService(provider)
		require.NotNil(t, srv)
		require.NoError(t, err)

		createdAt := time.Now().UTC()
		opts := []keystore.Option{
			keystore.WithID(testKeystoreID),
			keystore.WithController(testController),
			keystore.WithDelegateKeyType(testKeyType),
			keystore.WithRecipientKeyType(testKeyType),
			keystore.WithCreatedAt(&createdAt),
		}

		keystoreID, err := srv.Create(opts...)

		require.NotEmpty(t, keystoreID)
		require.NoError(t, err)
	})

	t.Run("Error: create delegate key", func(t *testing.T) {
		provider := mock.NewMockProvider()
		provider.MockKeyManager.CreateKeyErr = errors.New("create key error")

		srv, err := keystore.NewService(provider)
		require.NotNil(t, srv)
		require.NoError(t, err)

		keystoreID, err := srv.Create(keystore.WithID(testKeystoreID), keystore.WithDelegateKeyType(testKeyType))

		require.Empty(t, keystoreID)
		require.Error(t, err)
	})

	t.Run("Error: create recipient key", func(t *testing.T) {
		provider := mock.NewMockProvider()
		provider.MockKeyManager.CreateKeyErr = errors.New("create key error")

		srv, err := keystore.NewService(provider)
		require.NotNil(t, srv)
		require.NoError(t, err)

		keystoreID, err := srv.Create(keystore.WithID(testKeystoreID), keystore.WithRecipientKeyType(testKeyType))

		require.Empty(t, keystoreID)
		require.Error(t, err)
	})

	t.Run("Error: store put", func(t *testing.T) {
		provider := mock.NewMockProvider()
		provider.MockStorageProvider.Store.ErrPut = errors.New("store put error")

		srv, err := keystore.NewService(provider)
		require.NotNil(t, srv)
		require.NoError(t, err)

		keystoreID, err := srv.Create(keystore.WithID(testKeystoreID))
		require.Empty(t, keystoreID)
		require.Error(t, err)
	})
}

func TestGet(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider := mock.NewMockProvider()
		provider.MockStorageProvider.Store.Store[testKeystoreID] = keystoreBytes(t)

		srv, err := keystore.NewService(provider)
		require.NotNil(t, srv)
		require.NoError(t, err)

		k, err := srv.Get(testKeystoreID)

		require.NotNil(t, k)
		require.NoError(t, err)
	})

	t.Run("Error: store get", func(t *testing.T) {
		provider := mock.NewMockProvider()
		provider.MockStorageProvider.Store.ErrGet = errors.New("store get error")

		srv, err := keystore.NewService(provider)
		require.NotNil(t, srv)
		require.NoError(t, err)

		k, err := srv.Get(testKeystoreID)

		require.Nil(t, k)
		require.Error(t, err)
	})
}

func TestSave(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		srv, err := keystore.NewService(mock.NewMockProvider())
		require.NotNil(t, srv)
		require.NoError(t, err)

		k := testKeystore()
		err = srv.Save(&k)
		require.NoError(t, err)
	})

	t.Run("Error: store put", func(t *testing.T) {
		provider := mock.NewMockProvider()
		provider.MockStorageProvider.Store.ErrPut = errors.New("store put error")

		srv, err := keystore.NewService(provider)
		require.NotNil(t, srv)
		require.NoError(t, err)

		k := testKeystore()
		err = srv.Save(&k)
		require.Error(t, err)
	})
}

func testKeystore() keystore.Keystore {
	createdAt := time.Now().UTC()

	return keystore.Keystore{
		ID:                testKeystoreID,
		Controller:        testController,
		DelegateKeyID:     testKeyID,
		RecipientKeyID:    testKeyID,
		CreatedAt:         &createdAt,
		OperationalKeyIDs: []string{testKeyID},
	}
}

func keystoreBytes(t *testing.T) []byte {
	t.Helper()

	k := testKeystore()
	b, err := json.Marshal(&k)
	require.NoError(t, err)

	return b
}
