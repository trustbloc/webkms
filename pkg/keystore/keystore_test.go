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

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/storage"
	"github.com/trustbloc/edge-core/pkg/storage/mockstore"
)

var (
	validConfig = Config{
		Controller: "did:example:123456789",
	}

	missingControllerConfig = Config{
		Sequence: 0,
	}

	invalidStartingSequenceConfig = Config{
		Controller: "did:example:123456789",
		Sequence:   1,
	}
)

func TestNew(t *testing.T) {
	k := New(mockstore.NewMockStoreProvider())
	require.NotNil(t, k)
}

func TestKeystore_Create(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider := mockstore.NewMockStoreProvider()
		k := New(provider)
		require.NotNil(t, k)

		ID, err := k.Create(validConfig)

		require.NotEmpty(t, ID)
		require.NoError(t, err)
		assertStoredConfiguration(t, provider.Store.Store[configStoreKey])
	})
	t.Run("Config error: missing controller", func(t *testing.T) {
		k := New(mockstore.NewMockStoreProvider())
		require.NotNil(t, k)

		ID, err := k.Create(missingControllerConfig)

		require.Empty(t, ID)
		require.EqualError(t, err, fmt.Errorf(checkConfigErr, ErrMissingController).Error())
	})
	t.Run("Config error: invalid starting sequence", func(t *testing.T) {
		k := New(mockstore.NewMockStoreProvider())
		require.NotNil(t, k)

		ID, err := k.Create(invalidStartingSequenceConfig)

		require.Empty(t, ID)
		require.EqualError(t, err, fmt.Errorf(checkConfigErr, ErrInvalidStartingSequence).Error())
	})
	t.Run("CreateStore error: duplicate keystore", func(t *testing.T) {
		provider := mockstore.NewMockStoreProvider()
		provider.ErrCreateStore = storage.ErrDuplicateStore
		k := New(provider)
		require.NotNil(t, k)

		ID, err := k.Create(validConfig)

		require.Empty(t, ID)
		require.EqualError(t, err, fmt.Errorf(createStoreErr, ErrDuplicateKeystore).Error())
	})
	t.Run("CreateStore error: other", func(t *testing.T) {
		provider := mockstore.NewMockStoreProvider()
		provider.ErrCreateStore = errors.New("create store error")
		k := New(provider)
		require.NotNil(t, k)

		ID, err := k.Create(validConfig)

		require.Empty(t, ID)
		require.Error(t, err)
	})
	t.Run("OpenStore error", func(t *testing.T) {
		provider := mockstore.NewMockStoreProvider()
		provider.ErrOpenStoreHandle = errors.New("open store error")
		k := New(provider)
		require.NotNil(t, k)

		ID, err := k.Create(validConfig)

		require.Empty(t, ID)
		require.Error(t, err)
	})
	t.Run("Put store error", func(t *testing.T) {
		provider := mockstore.NewMockStoreProvider()
		provider.Store.ErrPut = errors.New("put error")
		k := New(provider)
		require.NotNil(t, k)

		ID, err := k.Create(validConfig)

		require.Empty(t, ID)
		require.Error(t, err)
	})
}

func assertStoredConfiguration(t *testing.T, b []byte) {
	t.Helper()

	var config Config
	err := json.Unmarshal(b, &config)

	require.NoError(t, err)
	require.Equal(t, validConfig.Controller, config.Controller)
	require.Equal(t, validConfig.Sequence, config.Sequence)
}
