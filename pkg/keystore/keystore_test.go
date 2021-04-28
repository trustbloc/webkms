/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package keystore_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
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

	t.Run("Failed to create default local KMS", func(t *testing.T) {
		k, err := keystore.New(
			keystore.WithPrimaryKeyURI("invalidKeyURI"),
			keystore.WithStorageProvider(mockstorage.NewMockStoreProvider()),
			keystore.WithSecretLock(&mocksecretlock.MockSecretLock{}),
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

func TestCreateAndExportKey(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		k := newKeystore(t, &mockkms.KeyManager{
			CrAndExportPubKeyID:    testKeyID,
			CrAndExportPubKeyValue: []byte("public key bytes"),
		})

		keyID, b, err := k.CreateAndExportKey(kms.ED25519)

		require.NotEmpty(t, keyID)
		require.NotNil(t, b)
		require.NoError(t, err)
	})

	t.Run("Failed to create and export a key", func(t *testing.T) {
		k := newKeystore(t, &mockkms.KeyManager{CrAndExportPubKeyErr: errors.New("create and export key error")})

		keyID, b, err := k.CreateAndExportKey(kms.ED25519)

		require.Empty(t, keyID)
		require.Nil(t, b)
		require.Error(t, err)
	})
}

func TestImportKey(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		tests := []struct {
			kt kms.KeyType
			pk interface{}
		}{
			{kms.ED25519, generateKey(t, kms.ED25519)},
			{kms.ECDSAP256TypeDER, generateKey(t, kms.ECDSAP256TypeDER)},
			{kms.ECDSAP384TypeDER, generateKey(t, kms.ECDSAP384TypeDER)},
			{kms.ECDSAP521TypeDER, generateKey(t, kms.ECDSAP521TypeDER)},
			{kms.ECDSAP256TypeIEEEP1363, generateKey(t, kms.ECDSAP256TypeIEEEP1363)},
			{kms.ECDSAP384TypeIEEEP1363, generateKey(t, kms.ECDSAP384TypeIEEEP1363)},
			{kms.ECDSAP521TypeIEEEP1363, generateKey(t, kms.ECDSAP521TypeIEEEP1363)},
		}

		for _, tt := range tests {
			k := newKeystore(t, &mockkms.KeyManager{
				ImportPrivateKeyID: testKeyID,
			})

			der, err := x509.MarshalPKCS8PrivateKey(tt.pk)
			require.NoError(t, err)

			keyID, err := k.ImportKey(der, tt.kt, testKeyID)

			require.NotEmpty(t, keyID)
			require.NoError(t, err)
		}
	})

	t.Run("Failed to parse PKCS8 private key", func(t *testing.T) {
		k := newKeystore(t, &mockkms.KeyManager{
			ImportPrivateKeyID: testKeyID,
		})

		keyID, err := k.ImportKey([]byte("not valid private key"), kms.ED25519, "")

		require.Empty(t, keyID)
		require.Error(t, err)
	})

	t.Run("Failed to import key: not supported key type", func(t *testing.T) {
		k := newKeystore(t, &mockkms.KeyManager{
			ImportPrivateKeyID: testKeyID,
		})

		privKey, err := rsa.GenerateKey(rand.Reader, 256) //nolint:gosec // test case
		require.NoError(t, err)

		der, err := x509.MarshalPKCS8PrivateKey(privKey)
		require.NoError(t, err)

		keyID, err := k.ImportKey(der, kms.RSARS256Type, "")

		require.Empty(t, keyID)
		require.Error(t, err)
	})

	t.Run("Failed to import private key", func(t *testing.T) {
		k := newKeystore(t, &mockkms.KeyManager{
			ImportPrivateKeyID:  testKeyID,
			ImportPrivateKeyErr: errors.New("import private key error"),
		})

		_, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		der, err := x509.MarshalPKCS8PrivateKey(privKey)
		require.NoError(t, err)

		keyID, err := k.ImportKey(der, kms.ED25519, "")

		require.Empty(t, keyID)
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

func generateKey(t *testing.T, kt kms.KeyType) interface{} {
	t.Helper()

	switch kt { //nolint:exhaustive // test cases
	case kms.ED25519:
		_, pk, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		return pk
	case kms.ECDSAP256TypeDER, kms.ECDSAP256TypeIEEEP1363:
		pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		return pk
	case kms.ECDSAP384TypeDER, kms.ECDSAP384TypeIEEEP1363:
		pk, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		require.NoError(t, err)

		return pk
	case kms.ECDSAP521TypeDER, kms.ECDSAP521TypeIEEEP1363:
		pk, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		require.NoError(t, err)

		return pk
	default:
		require.Fail(t, "not supported key type")

		return nil
	}
}
