/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"errors"
	"fmt"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/stretchr/testify/require"

	mockkms "github.com/trustbloc/hub-kms/pkg/internal/mock/kms"
	"github.com/trustbloc/hub-kms/pkg/keystore"
)

const (
	testKeystoreID = "keystoreID"
	testKeyType    = kms.ED25519
	testKeyID      = "keyID"
	testMessage    = "test message"
)

func TestNewService(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		srv := NewService(mockkms.NewMockProvider())
		require.NotNil(t, srv)
	})
}

func TestCreateKey(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockKeystore.Store[testKeystoreID] = &keystore.Keystore{
			ID: testKeystoreID,
		}
		provider.MockKMS.CreateKeyID = testKeyID

		srv := NewService(provider)
		require.NotNil(t, srv)

		keyID, err := srv.CreateKey(testKeystoreID, testKeyType)
		require.NotEmpty(t, keyID)
		require.NoError(t, err)

		k, ok := provider.MockKeystore.Store[testKeystoreID]
		require.True(t, ok)
		require.Equal(t, keyID, k.KeyIDs[0])
	})

	t.Run("Error: key create", func(t *testing.T) {
		createKeyError := errors.New("create key error")
		provider := mockkms.NewMockProvider()
		provider.MockKMS.CreateKeyErr = createKeyError

		srv := NewService(provider)
		require.NotNil(t, srv)

		keyID, err := srv.CreateKey(testKeystoreID, testKeyType)

		require.Empty(t, keyID)
		require.EqualError(t, err, fmt.Errorf(createKeyErr, createKeyError).Error())
	})

	t.Run("Error: get keystore", func(t *testing.T) {
		keystoreGetError := errors.New("get keystore error")
		provider := mockkms.NewMockProvider()
		provider.MockKeystore.ErrGet = keystoreGetError

		srv := NewService(provider)
		require.NotNil(t, srv)

		keyID, err := srv.CreateKey(testKeystoreID, testKeyType)

		require.Empty(t, keyID)
		require.EqualError(t, err, fmt.Errorf(getKeystoreErr, keystoreGetError).Error())
	})

	t.Run("Error: save keystore", func(t *testing.T) {
		keystoreSaveError := errors.New("save keystore error")
		provider := mockkms.NewMockProvider()
		provider.MockKeystore.ErrSave = keystoreSaveError
		provider.MockKeystore.Store[testKeystoreID] = &keystore.Keystore{
			ID: testKeystoreID,
		}
		provider.MockKMS.CreateKeyID = testKeyID

		srv := NewService(provider)
		require.NotNil(t, srv)

		keyID, err := srv.CreateKey(testKeystoreID, testKeyType)

		require.Empty(t, keyID)
		require.EqualError(t, err, fmt.Errorf(saveKeystoreErr, keystoreSaveError).Error())
	})
}

func TestSign(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockKeystore.Store[testKeystoreID] = &keystore.Keystore{
			ID:     testKeystoreID,
			KeyIDs: []string{testKeyID},
		}
		provider.MockCrypto.SignValue = []byte("signature")

		srv := NewService(provider)
		require.NotNil(t, srv)

		sig, err := srv.Sign(testKeystoreID, testKeyID, []byte(testMessage))

		require.NotEmpty(t, sig)
		require.NoError(t, err)
	})

	t.Run("Error: get keystore", func(t *testing.T) {
		keystoreGetError := errors.New("get keystore error")
		provider := mockkms.NewMockProvider()
		provider.MockKeystore.ErrGet = keystoreGetError

		srv := NewService(provider)
		require.NotNil(t, srv)

		sig, err := srv.Sign(testKeystoreID, testKeyID, []byte(testMessage))

		require.Empty(t, sig)
		require.EqualError(t, err, fmt.Errorf(getKeystoreErr, keystoreGetError).Error())
	})

	t.Run("Error: no keys defined", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockKeystore.Store[testKeystoreID] = &keystore.Keystore{
			ID: testKeystoreID,
		}
		srv := NewService(provider)
		require.NotNil(t, srv)

		sig, err := srv.Sign(testKeystoreID, testKeyID, []byte(testMessage))

		require.Empty(t, sig)
		require.EqualError(t, err, noKeysErr)
	})

	t.Run("Error: invalid key ID", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockKeystore.Store[testKeystoreID] = &keystore.Keystore{
			ID:     testKeystoreID,
			KeyIDs: []string{testKeyID},
		}
		srv := NewService(provider)
		require.NotNil(t, srv)

		sig, err := srv.Sign(testKeystoreID, "invalidKeyID", []byte(testMessage))

		require.Empty(t, sig)
		require.EqualError(t, err, invalidKeyIDErr)
	})

	t.Run("Error: get key", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockKeystore.Store[testKeystoreID] = &keystore.Keystore{
			ID:     testKeystoreID,
			KeyIDs: []string{testKeyID},
		}

		getKeyError := errors.New("get key error")
		provider.MockKMS.GetKeyErr = getKeyError

		srv := NewService(provider)
		require.NotNil(t, srv)

		sig, err := srv.Sign(testKeystoreID, testKeyID, []byte(testMessage))

		require.Empty(t, sig)
		require.EqualError(t, err, fmt.Errorf(getKeyErr, getKeyError).Error())
	})
}
