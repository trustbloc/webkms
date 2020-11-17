/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	mockcrypto "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/stretchr/testify/require"

	mockkeystore "github.com/trustbloc/hub-kms/pkg/internal/mock/keystore"
	"github.com/trustbloc/hub-kms/pkg/keystore"
	"github.com/trustbloc/hub-kms/pkg/kms"
)

func TestNewKMSServiceCreator(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		creator := kms.NewServiceCreator(newConfig())
		req := buildReqWithSecretHeader(t, "p@ssphrase")

		srv, err := creator(req)

		require.NotNil(t, srv)
		require.NoError(t, err)
	})

	t.Run("Error: passphrase is empty", func(t *testing.T) {
		creator := kms.NewServiceCreator(newConfig())
		req := buildReqWithSecretHeader(t, "")

		srv, err := creator(req)

		require.Nil(t, srv)
		require.Error(t, err)
		require.Equal(t, "passphrase is empty", err.Error())
	})

	t.Run("Error: can't open store", func(t *testing.T) {
		p := mockstorage.NewMockStoreProvider()
		p.ErrOpenStoreHandle = errors.New("open store err")

		creator := kms.NewServiceCreator(newConfig(withStorageProvider(p)))
		req := buildReqWithSecretHeader(t, "p@ssphrase")

		srv, err := creator(req)

		require.Nil(t, srv)
		require.Error(t, err)
	})

	t.Run("Error: can't resolve KMS storage", func(t *testing.T) {
		creator := kms.NewServiceCreator(newConfig(withOperationalKMSStorageResolverErr(errors.New("resolver error"))))
		req := buildReqWithSecretHeader(t, "p@ssphrase")

		srv, err := creator(req)

		require.Nil(t, srv)
		require.Error(t, err)
	})
}

func buildReqWithSecretHeader(t *testing.T, passphrase string) *http.Request {
	t.Helper()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", nil)
	require.NoError(t, err)

	req.Header.Add("Hub-Kms-Secret", passphrase)

	req = mux.SetURLVars(req, map[string]string{
		"keystoreID": testKeystoreID,
		"keyID":      testKeyID,
	})

	return req
}

type options struct {
	keystoreService                  keystore.Service
	cryptoService                    crypto.Crypto
	storageProvider                  storage.Provider
	operationalKMSStorageResolverErr error
}

type optionFn func(opts *options)

func newConfig(opts ...optionFn) *kms.Config {
	cOpts := &options{
		keystoreService:                  mockkeystore.NewMockService(),
		cryptoService:                    &mockcrypto.Crypto{},
		storageProvider:                  mockstorage.NewMockStoreProvider(),
		operationalKMSStorageResolverErr: nil,
	}

	for i := range opts {
		opts[i](cOpts)
	}

	config := &kms.Config{
		KeystoreService:               cOpts.keystoreService,
		CryptoService:                 cOpts.cryptoService,
		OperationalKMSStorageResolver: func(string) (storage.Provider, error) { return cOpts.storageProvider, nil },
	}

	if cOpts.operationalKMSStorageResolverErr != nil {
		config.OperationalKMSStorageResolver = func(string) (storage.Provider, error) {
			return nil, cOpts.operationalKMSStorageResolverErr
		}
	}

	return config
}

func withStorageProvider(p storage.Provider) optionFn {
	return func(o *options) {
		o.storageProvider = p
	}
}

func withOperationalKMSStorageResolverErr(err error) optionFn {
	return func(o *options) {
		o.operationalKMSStorageResolverErr = err
	}
}
