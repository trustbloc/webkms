/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sds_test

import (
	"crypto/tls"
	"errors"
	"testing"

	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/mac"
	"github.com/google/tink/go/signature"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdh"
	mockcrypto "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	"github.com/stretchr/testify/require"

	mockkeystore "github.com/trustbloc/hub-kms/pkg/internal/mock/keystore"
	"github.com/trustbloc/hub-kms/pkg/keystore"
	"github.com/trustbloc/hub-kms/pkg/storage/sds"
)

const (
	testKeystoreID   = "keystoreID"
	testSDSServerURL = "sds.example.com"
)

func TestNewProvider(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		kh, err := keyset.NewHandle(ecdh.ECDH256KWAES256GCMKeyTemplate())
		require.NoError(t, err)

		srv := mockkeystore.NewMockService()
		srv.GetKeystoreValue = &keystore.Keystore{
			ID: testKeystoreID,
		}
		srv.GetKeyHandleValue = kh

		p, err := sds.NewStorageProvider(buildConfig(srv))

		require.NotNil(t, p)
		require.NoError(t, err)
	})

	t.Run("Fail to retrieve keystore", func(t *testing.T) {
		srv := mockkeystore.NewMockService()
		srv.GetErr = errors.New("get err")

		p, err := sds.NewStorageProvider(buildConfig(srv))

		require.Nil(t, p)
		require.Error(t, err)
	})

	t.Run("Fail to create REST provider: get MAC key handle", func(t *testing.T) {
		srv := mockkeystore.NewMockService()
		srv.GetKeystoreValue = &keystore.Keystore{
			ID: testKeystoreID,
		}
		srv.GetKeyHandleErr = errors.New("get key handle error")

		p, err := sds.NewStorageProvider(buildConfig(srv))

		require.Nil(t, p)
		require.Error(t, err)
	})

	t.Run("Fail to create REST provider: compute MAC for index name", func(t *testing.T) {
		srv := mockkeystore.NewMockService()
		srv.GetKeystoreValue = &keystore.Keystore{
			ID: testKeystoreID,
		}

		config := &sds.Config{
			KeystoreService: srv,
			CryptoService:   &mockcrypto.Crypto{ComputeMACErr: errors.New("compute mac error")},
			TLSConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
			SDSServerURL:    testSDSServerURL,
			KeystoreID:      testKeystoreID,
		}

		p, err := sds.NewStorageProvider(config)

		require.Nil(t, p)
		require.Error(t, err)
	})

	t.Run("Fail to create EncryptedFormatter: get public key handle for recipient key", func(t *testing.T) {
		kh, err := keyset.NewHandle(mac.HMACSHA256Tag256KeyTemplate())
		require.NoError(t, err)

		srv := mockkeystore.NewMockService()
		srv.GetKeystoreValue = &keystore.Keystore{
			ID: testKeystoreID,
		}
		srv.GetKeyHandleValue = kh

		p, err := sds.NewStorageProvider(buildConfig(srv))

		require.Nil(t, p)
		require.Error(t, err)
	})

	t.Run("Fail to create EncryptedFormatter: export keyset to the writer", func(t *testing.T) {
		kh, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
		require.NoError(t, err)

		srv := mockkeystore.NewMockService()
		srv.GetKeystoreValue = &keystore.Keystore{
			ID: testKeystoreID,
		}
		srv.GetKeyHandleValue = kh

		p, err := sds.NewStorageProvider(buildConfig(srv))

		require.Nil(t, p)
		require.Error(t, err)
	})

	t.Run("Fail to create EncryptedFormatter: get key manager", func(t *testing.T) {
		kh, err := keyset.NewHandle(ecdh.ECDH256KWAES256GCMKeyTemplate())
		require.NoError(t, err)

		srv := mockkeystore.NewMockService()
		srv.GetKeystoreValue = &keystore.Keystore{
			ID: testKeystoreID,
		}
		srv.GetKeyHandleValue = kh
		srv.KeyManagerErr = errors.New("get key manager error")

		p, err := sds.NewStorageProvider(buildConfig(srv))

		require.Nil(t, p)
		require.Error(t, err)
	})
}

func buildConfig(keystoreService keystore.Service) *sds.Config {
	return &sds.Config{
		KeystoreService: keystoreService,
		CryptoService:   &mockcrypto.Crypto{},
		TLSConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		SDSServerURL:    testSDSServerURL,
		KeystoreID:      testKeystoreID,
	}
}
