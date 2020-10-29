/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms_test

import (
	"errors"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/mock/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/hub-kms/pkg/kms"
)

const (
	keyURI = "local-lock://test"
)

func TestNewLocalKMS(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		localKMS, err := kms.NewLocalKMS(keyURI, storage.NewMockStoreProvider(), &noop.NoLock{})

		require.NotNil(t, localKMS)
		require.NoError(t, err)
	})

	t.Run("Error opening master key store", func(t *testing.T) {
		storageProv := storage.NewMockStoreProvider()
		storageProv.ErrOpenStoreHandle = errors.New("open store error")

		localKMS, err := kms.NewLocalKMS(keyURI, storageProv, &noop.NoLock{})

		require.Nil(t, localKMS)
		require.Error(t, err)
	})

	t.Run("Error getting from master key store", func(t *testing.T) {
		storageProv := storage.NewMockStoreProvider()
		storageProv.Store.ErrGet = errors.New("store get error")

		localKMS, err := kms.NewLocalKMS(keyURI, storageProv, &noop.NoLock{})

		require.Nil(t, localKMS)
		require.Error(t, err)
	})

	t.Run("Error saving into master key store", func(t *testing.T) {
		storageProv := storage.NewMockStoreProvider()
		storageProv.Store.ErrPut = errors.New("store put error")

		localKMS, err := kms.NewLocalKMS(keyURI, storageProv, &noop.NoLock{})

		require.Nil(t, localKMS)
		require.Error(t, err)
	})

	t.Run("Error encrypting secret lock", func(t *testing.T) {
		secLock := &secretlock.MockSecretLock{}
		secLock.ErrEncrypt = errors.New("encrypt error")

		localKMS, err := kms.NewLocalKMS(keyURI, storage.NewMockStoreProvider(), secLock)

		require.Nil(t, localKMS)
		require.Error(t, err)
	})
}
