/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms_test

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"testing"

	"github.com/gorilla/mux"
	mockcrypto "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	mocksecretlock "github.com/hyperledger/aries-framework-go/pkg/mock/secretlock"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/stretchr/testify/require"

	mockkeystore "github.com/trustbloc/hub-kms/pkg/internal/mock/keystore"
	"github.com/trustbloc/hub-kms/pkg/kms"
)

func TestNewKMSServiceCreator(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		creator := kms.NewServiceCreator(newConfig())
		req := buildReq(t)

		srv, err := creator(req)

		require.NotNil(t, srv)
		require.NoError(t, err)
	})

	t.Run("Error: resolve secret lock", func(t *testing.T) {
		creator := kms.NewServiceCreator(newConfig(withSecretLockResolverErr(errors.New("resolve error"))))
		req := buildReq(t)

		srv, err := creator(req)

		require.Nil(t, srv)
		require.Error(t, err)
		require.Contains(t, err.Error(), "resolve error")
	})

	t.Run("Error: can't open store", func(t *testing.T) {
		p := mockstorage.NewMockStoreProvider()
		p.ErrOpenStoreHandle = errors.New("open store err")

		creator := kms.NewServiceCreator(newConfig(withStorageProvider(p)))
		req := buildReq(t)

		srv, err := creator(req)

		require.Nil(t, srv)
		require.Error(t, err)
	})

	t.Run("Error: can't resolve KMS storage", func(t *testing.T) {
		creator := kms.NewServiceCreator(newConfig(withKMSStorageResolverErr(errors.New("resolver error"))))
		req := buildReq(t)

		srv, err := creator(req)

		require.Nil(t, srv)
		require.Error(t, err)
	})
}

func buildReq(t *testing.T) *http.Request {
	t.Helper()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", nil)
	require.NoError(t, err)

	req = mux.SetURLVars(req, map[string]string{
		"keystoreID": testKeystoreID,
		"keyID":      testKeyID,
	})

	return req
}

func randomBytes(size uint32) []byte {
	buf := make([]byte, size)

	_, err := rand.Read(buf)
	if err != nil {
		panic(err) // out of randomness, should never happen
	}

	return buf
}

type options struct {
	storageProvider       storage.Provider
	secretLock            secretlock.Service
	secretLockResolverErr error
	kmsStorageResolverErr error
}

type optionFn func(opts *options)

func newConfig(opts ...optionFn) *kms.Config {
	b := randomBytes(uint32(32))
	secLock := &mocksecretlock.MockSecretLock{
		ValEncrypt: string(b),
		ValDecrypt: string(b),
	}

	cOpts := &options{
		storageProvider:       mockstorage.NewMockStoreProvider(),
		secretLock:            secLock,
		kmsStorageResolverErr: nil,
		secretLockResolverErr: nil,
	}

	for i := range opts {
		opts[i](cOpts)
	}

	config := &kms.Config{
		KeystoreService:    mockkeystore.NewMockService(),
		CryptoService:      &mockcrypto.Crypto{},
		KMSStorageResolver: func(string) (storage.Provider, error) { return cOpts.storageProvider, nil },
		SecretLockResolver: func(string, *http.Request) (secretlock.Service, error) { return cOpts.secretLock, nil },
	}

	if cOpts.kmsStorageResolverErr != nil {
		config.KMSStorageResolver = func(string) (storage.Provider, error) {
			return nil, cOpts.kmsStorageResolverErr
		}
	}

	if cOpts.secretLockResolverErr != nil {
		config.SecretLockResolver = func(string, *http.Request) (secretlock.Service, error) {
			return nil, cOpts.secretLockResolverErr
		}
	}

	return config
}

func withStorageProvider(p storage.Provider) optionFn {
	return func(o *options) {
		o.storageProvider = p
	}
}

func withKMSStorageResolverErr(err error) optionFn {
	return func(o *options) {
		o.kmsStorageResolverErr = err
	}
}

func withSecretLockResolverErr(err error) optionFn {
	return func(o *options) {
		o.secretLockResolverErr = err
	}
}
