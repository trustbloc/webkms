/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package keystore_test

import (
	"errors"
	"testing"

	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/signature"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	mocksecretlock "github.com/hyperledger/aries-framework-go/pkg/mock/secretlock"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/kms/pkg/keystore"
)

const testKeyID = "testKeyID"

func TestNew(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		k, err := keystore.New()

		require.NotNil(t, k)
		require.NoError(t, err)
	})

	t.Run("Success with custom options", func(t *testing.T) {
		k, err := keystore.New(
			keystore.WithPrimaryKeyURI("local-lock://test"),
			keystore.WithStorageProvider(mockstorage.NewMockStoreProvider()),
			keystore.WithSecretLock(&mocksecretlock.MockSecretLock{}),
		)

		require.NotNil(t, k)
		require.NoError(t, err)
	})

	t.Run("Failed to create key manager", func(t *testing.T) {
		k, err := keystore.New(
			keystore.WithKMSCreator(func(kms.Provider) (kms.KeyManager, error) {
				return nil, errors.New("kms creator error")
			}),
		)

		require.Nil(t, k)
		require.Error(t, err)
	})
}

func TestCreateKey(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		k := newKeystore(t, &mockkms.KeyManager{CreateKeyID: testKeyID})

		keyID, err := k.CreateKey(kms.ED25519)

		require.NotEmpty(t, keyID)
		require.NoError(t, err)
	})

	t.Run("Failed to create a key", func(t *testing.T) {
		k := newKeystore(t, &mockkms.KeyManager{CreateKeyErr: errors.New("create key error")})

		keyID, err := k.CreateKey(kms.ED25519)

		require.Empty(t, keyID)
		require.Error(t, err)
	})
}

func TestExportKey(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		k := newKeystore(t, &mockkms.KeyManager{ExportPubKeyBytesValue: []byte("public key bytes")})

		b, err := k.ExportKey(testKeyID)

		require.NotNil(t, b)
		require.NoError(t, err)
	})

	t.Run("Failed to export a key", func(t *testing.T) {
		k := newKeystore(t, &mockkms.KeyManager{ExportPubKeyBytesErr: errors.New("export key error")})

		keyID, err := k.ExportKey(testKeyID)

		require.Nil(t, keyID)
		require.Error(t, err)
	})
}

func TestGetKeyHandle(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		key, err := keyset.NewHandle(signature.ED25519KeyTemplate())
		require.NoError(t, err)

		k := newKeystore(t, &mockkms.KeyManager{GetKeyValue: key})

		kh, err := k.GetKeyHandle(testKeyID)

		require.NotNil(t, kh)
		require.NoError(t, err)
	})

	t.Run("Failed to get key handle", func(t *testing.T) {
		k := newKeystore(t, &mockkms.KeyManager{GetKeyErr: errors.New("get key handle error")})

		kh, err := k.GetKeyHandle(testKeyID)

		require.Nil(t, kh)
		require.Error(t, err)
	})
}

func TestKeyManager(t *testing.T) {
	k, err := keystore.New()
	require.NotNil(t, k)
	require.NoError(t, err)

	keyManager := k.KeyManager()

	require.NotNil(t, keyManager)
}

func newKeystore(t *testing.T, km kms.KeyManager) keystore.Keystore {
	t.Helper()

	k, err := keystore.New(keystore.WithKMSCreator(func(kms.Provider) (kms.KeyManager, error) {
		return km, nil
	}))
	require.NotNil(t, k)
	require.NoError(t, err)

	return k
}
