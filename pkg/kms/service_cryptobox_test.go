/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	mockkms "github.com/trustbloc/hub-kms/pkg/internal/mock/kms"
	"github.com/trustbloc/hub-kms/pkg/keystore"
	"github.com/trustbloc/hub-kms/pkg/kms"
)

const (
	testTheirPub = "their pub"
	testMyPub    = "my pub"
)

func TestEasy(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockCryptoBox.EasyValue = []byte("easy value")

		k := &keystore.Keystore{
			ID:     testKeystoreID,
			KeyIDs: []string{testKeyID},
		}
		provider.MockKeystoreService.GetKeystoreValue = k

		srv := kms.NewService(provider)
		require.NotNil(t, srv)

		cipher, err := srv.Easy(context.Background(), testKeystoreID, testKeyID, []byte(testMessage), []byte(testNonce),
			[]byte(testTheirPub))

		require.NotEmpty(t, cipher)
		require.NoError(t, err)
	})

	t.Run("Error: get keystore", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockCryptoBox.EasyValue = []byte("easy value")
		provider.MockKeystoreService.GetErr = errors.New("get keystore error")

		srv := kms.NewService(provider)
		require.NotNil(t, srv)

		cipher, err := srv.Easy(context.Background(), testKeystoreID, testKeyID, []byte(testMessage), []byte(testNonce),
			[]byte(testTheirPub))

		require.Empty(t, cipher)
		require.Error(t, err)
		require.Equal(t, "get keystore failed: get keystore error", err.Error())
	})

	t.Run("Error: no keys defined", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockCryptoBox.EasyValue = []byte("easy value")

		k := &keystore.Keystore{
			ID: testKeystoreID,
		}
		provider.MockKeystoreService.GetKeystoreValue = k

		srv := kms.NewService(provider)
		require.NotNil(t, srv)

		cipher, err := srv.Easy(context.Background(), testKeystoreID, testKeyID, []byte(testMessage), []byte(testNonce),
			[]byte(testTheirPub))

		require.Empty(t, cipher)
		require.Error(t, err)
		require.Equal(t, "no keys defined", err.Error())
	})

	t.Run("Error: invalid key ID", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockCryptoBox.EasyValue = []byte("easy value")

		k := &keystore.Keystore{
			ID:     testKeystoreID,
			KeyIDs: []string{testKeyID},
		}
		provider.MockKeystoreService.GetKeystoreValue = k

		srv := kms.NewService(provider)
		require.NotNil(t, srv)

		cipher, err := srv.Easy(context.Background(), testKeystoreID, "invalidKeyID", []byte(testMessage),
			[]byte(testNonce), []byte(testTheirPub))

		require.Empty(t, cipher)
		require.Error(t, err)
		require.Equal(t, "invalid key", err.Error())
	})

	t.Run("Error: easy message failed", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockCryptoBox.EasyErr = errors.New("easy error")

		k := &keystore.Keystore{
			ID:     testKeystoreID,
			KeyIDs: []string{testKeyID},
		}
		provider.MockKeystoreService.GetKeystoreValue = k

		srv := kms.NewService(provider)
		require.NotNil(t, srv)

		cipher, err := srv.Easy(context.Background(), testKeystoreID, testKeyID, []byte(testMessage), []byte(testNonce),
			[]byte(testTheirPub))

		require.Empty(t, cipher)
		require.Error(t, err)
		require.Equal(t, "easy message failed: easy error", err.Error())
	})
}

func TestEasyOpen(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockCryptoBox.EasyOpenValue = []byte("easy open value")

		k := &keystore.Keystore{
			ID: testKeystoreID,
		}
		provider.MockKeystoreService.GetKeystoreValue = k

		srv := kms.NewService(provider)
		require.NotNil(t, srv)

		plain, err := srv.EasyOpen(context.Background(), testKeystoreID, []byte(testCipherText), []byte(testNonce),
			[]byte(testTheirPub), []byte(testMyPub))

		require.NotEmpty(t, plain)
		require.NoError(t, err)
	})

	t.Run("Error: get keystore", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockCryptoBox.EasyOpenValue = []byte("easy open value")
		provider.MockKeystoreService.GetErr = errors.New("get keystore error")

		srv := kms.NewService(provider)
		require.NotNil(t, srv)

		plain, err := srv.EasyOpen(context.Background(), testKeystoreID, []byte(testCipherText), []byte(testNonce),
			[]byte(testTheirPub), []byte(testMyPub))

		require.Empty(t, plain)
		require.Error(t, err)
		require.Equal(t, "get keystore failed: get keystore error", err.Error())
	})

	t.Run("Error: easy open message failed", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockCryptoBox.EasyOpenErr = errors.New("easy open error")

		k := &keystore.Keystore{
			ID: testKeystoreID,
		}
		provider.MockKeystoreService.GetKeystoreValue = k

		srv := kms.NewService(provider)
		require.NotNil(t, srv)

		plain, err := srv.EasyOpen(context.Background(), testKeystoreID, []byte(testCipherText), []byte(testNonce),
			[]byte(testTheirPub), []byte(testMyPub))

		require.Empty(t, plain)
		require.Error(t, err)
		require.Equal(t, "easy open message failed: easy open error", err.Error())
	})
}

func TestSealOpen(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockCryptoBox.SealOpenValue = []byte("seal open value")

		k := &keystore.Keystore{
			ID: testKeystoreID,
		}
		provider.MockKeystoreService.GetKeystoreValue = k

		srv := kms.NewService(provider)
		require.NotNil(t, srv)

		plain, err := srv.SealOpen(context.Background(), testKeystoreID, []byte(testCipherText), []byte(testMyPub))

		require.NotEmpty(t, plain)
		require.NoError(t, err)
	})

	t.Run("Error: get keystore", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockCryptoBox.SealOpenValue = []byte("seal open value")
		provider.MockKeystoreService.GetErr = errors.New("get keystore error")

		srv := kms.NewService(provider)
		require.NotNil(t, srv)

		plain, err := srv.SealOpen(context.Background(), testKeystoreID, []byte(testCipherText), []byte(testMyPub))

		require.Empty(t, plain)
		require.Error(t, err)
		require.Equal(t, "get keystore failed: get keystore error", err.Error())
	})

	t.Run("Error: easy open message failed", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockCryptoBox.SealOpenErr = errors.New("seal open error")

		k := &keystore.Keystore{
			ID: testKeystoreID,
		}
		provider.MockKeystoreService.GetKeystoreValue = k

		srv := kms.NewService(provider)
		require.NotNil(t, srv)

		plain, err := srv.SealOpen(context.Background(), testKeystoreID, []byte(testCipherText), []byte(testMyPub))

		require.Empty(t, plain)
		require.Error(t, err)
		require.Equal(t, "seal open payload failed: seal open error", err.Error())
	})
}
