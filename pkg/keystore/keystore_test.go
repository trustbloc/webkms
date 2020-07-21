/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package keystore

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/storage"

	"github.com/trustbloc/hub-kms/pkg/internal/mock/provider"
)

var (
	testKeystoreID = "urn:uuid:85149342-7f26-4dc1-a77a-345f4a1102d5"

	validConfig = Configuration{
		Controller: "did:example:123456789",
	}

	missingControllerConfig = Configuration{
		Sequence: 0,
	}

	invalidStartingSequenceConfig = Configuration{
		Controller: "did:example:123456789",
		Sequence:   1,
	}
)

func TestNew(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		k, err := New(testKeystoreID, provider.NewMockProvider())

		require.NotNil(t, k)
		require.NoError(t, err)
	})
	t.Run("Error: invalid keystore", func(t *testing.T) {
		provider := provider.NewMockProvider()
		provider.MockStorage.ErrOpenStoreHandle = ErrInvalidKeystore

		k, err := New(testKeystoreID, provider)

		require.Nil(t, k)
		require.EqualError(t, err, fmt.Errorf(openStoreErr, ErrInvalidKeystore).Error())
	})
	t.Run("Error: create kms", func(t *testing.T) {
		provider := provider.NewMockProvider()
		provider.KMSCreatorErr = errors.New("create kms error")

		k, err := New(testKeystoreID, provider)

		require.Nil(t, k)
		require.Error(t, err)
	})
}

func TestCreateKeystore(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		storageProvider := provider.NewMockProvider().MockStorage

		kID, err := CreateKeystore(validConfig, storageProvider)

		require.NotEmpty(t, kID)
		require.NoError(t, err)
		assertStoredConfiguration(t, storageProvider.Store.Store[configStoreKey])
	})
	t.Run("Config error: missing controller", func(t *testing.T) {
		kID, err := CreateKeystore(missingControllerConfig, provider.NewMockProvider().MockStorage)

		require.Empty(t, kID)
		require.EqualError(t, err, fmt.Errorf(validateConfigErr, ErrMissingController).Error())
	})
	t.Run("Config error: invalid starting sequence", func(t *testing.T) {
		kID, err := CreateKeystore(invalidStartingSequenceConfig, provider.NewMockProvider().MockStorage)

		require.Empty(t, kID)
		require.EqualError(t, err, fmt.Errorf(validateConfigErr, ErrInvalidStartingSequence).Error())
	})
	t.Run("CreateStore error: duplicate keystore", func(t *testing.T) {
		storageProvider := provider.NewMockProvider().MockStorage
		storageProvider.ErrCreateStore = storage.ErrDuplicateStore

		kID, err := CreateKeystore(validConfig, storageProvider)

		require.Empty(t, kID)
		require.EqualError(t, err, fmt.Errorf(createStoreErr, ErrDuplicateKeystore).Error())
	})
	t.Run("CreateStore error: other", func(t *testing.T) {
		storageProvider := provider.NewMockProvider().MockStorage
		storageProvider.ErrCreateStore = errors.New("create store error")

		kID, err := CreateKeystore(validConfig, storageProvider)

		require.Empty(t, kID)
		require.Error(t, err)
	})
	t.Run("OpenStore error", func(t *testing.T) {
		storageProvider := provider.NewMockProvider().MockStorage
		storageProvider.ErrOpenStoreHandle = errors.New("open store error")

		kID, err := CreateKeystore(validConfig, storageProvider)

		require.Empty(t, kID)
		require.Error(t, err)
	})
	t.Run("Put store error", func(t *testing.T) {
		storageProvider := provider.NewMockProvider().MockStorage
		storageProvider.Store.ErrPut = errors.New("put error")

		kID, err := CreateKeystore(validConfig, storageProvider)

		require.Empty(t, kID)
		require.Error(t, err)
	})
}

func TestCreateKey(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider := provider.NewMockProvider()
		provider.MockKMS.CreateKeyID = testKeystoreID
		k, err := New(testKeystoreID, provider)
		require.NotNil(t, k)
		require.NoError(t, err)

		keyID, err := k.CreateKey(kms.ED25519Type)

		require.NotEmpty(t, keyID)
		require.NoError(t, err)
	})
	t.Run("Create key error", func(t *testing.T) {
		provider := provider.NewMockProvider()
		provider.MockKMS.CreateKeyErr = errors.New("create key error")
		k, err := New(testKeystoreID, provider)
		require.NotNil(t, k)
		require.NoError(t, err)

		keyID, err := k.CreateKey(kms.ED25519Type)

		require.Empty(t, keyID)
		require.Error(t, err)
	})
	t.Run("Put store error", func(t *testing.T) {
		provider := provider.NewMockProvider()
		provider.MockStorage.Store.ErrPut = errors.New("put error")
		k, err := New(testKeystoreID, provider)
		require.NotNil(t, k)
		require.NoError(t, err)

		keyID, err := k.CreateKey(kms.ED25519Type)

		require.Empty(t, keyID)
		require.Error(t, err)
	})
}

func assertStoredConfiguration(t *testing.T, b []byte) {
	t.Helper()

	var config Configuration
	err := json.Unmarshal(b, &config)

	require.NoError(t, err)
	require.Equal(t, validConfig.Controller, config.Controller)
	require.Equal(t, validConfig.Sequence, config.Sequence)
}
