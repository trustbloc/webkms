/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/hub-kms/pkg/internal/mock/keystore"
	"github.com/trustbloc/hub-kms/pkg/kms"
)

const (
	//nolint:gosec // potential hardcoded credentials
	passphraseReqFormat = `{
	  "passphrase": "%s"
	}`
)

func TestNewKMSServiceCreator(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		creator := kms.NewKMSServiceCreator(keystore.NewMockRepository(), storage.NewMockStoreProvider())
		req := buildPassphraseReq(t, "p@ssphrase")

		srv, err := creator(req)

		require.NotNil(t, srv)
		require.NoError(t, err)

		// creator should not drain the request body
		body, err := ioutil.ReadAll(req.Body)
		require.True(t, len(body) > 0)
		require.NoError(t, err)
	})

	t.Run("Error: received empty request", func(t *testing.T) {
		creator := kms.NewKMSServiceCreator(keystore.NewMockRepository(), storage.NewMockStoreProvider())
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", bytes.NewBuffer([]byte("")))
		require.NoError(t, err)

		srv, err := creator(req)

		require.Nil(t, srv)
		require.Error(t, err)
		require.Equal(t, "EOF", err.Error())
	})

	t.Run("Error: passphrase is empty", func(t *testing.T) {
		creator := kms.NewKMSServiceCreator(keystore.NewMockRepository(), storage.NewMockStoreProvider())
		req := buildPassphraseReq(t, "")

		srv, err := creator(req)

		require.Nil(t, srv)
		require.Error(t, err)
		require.Equal(t, "passphrase is empty", err.Error())
	})

	t.Run("Error: can't open store", func(t *testing.T) {
		storageProv := storage.NewMockStoreProvider()
		storageProv.ErrOpenStoreHandle = errors.New("open store err")
		creator := kms.NewKMSServiceCreator(keystore.NewMockRepository(), storageProv)
		req := buildPassphraseReq(t, "p@ssphrase")

		srv, err := creator(req)

		require.Nil(t, srv)
		require.Error(t, err)
	})
}

func buildPassphraseReq(t *testing.T, passphrase string) *http.Request {
	t.Helper()

	payload := fmt.Sprintf(passphraseReqFormat, passphrase)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", bytes.NewBuffer([]byte(payload)))
	require.NoError(t, err)

	req = mux.SetURLVars(req, map[string]string{
		"keystoreID": testKeystoreID,
		"keyID":      testKeyID,
	})

	return req
}
