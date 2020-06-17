/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/hub-kms/pkg/mock/keystore"
)

const testKeystoreConfiguration = `{
  "sequence": 0,
  "controller": "did:example:123456789"
}`

// errReader returns an error when reading its body
type errReader int

func (errReader) Read(_ []byte) (n int, err error) {
	return 0, errors.New("read error")
}

func TestNew(t *testing.T) {
	srv := New(keystore.NewMockProvider())
	require.NotNil(t, srv)
}

func TestCreateKeyStoreHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, "", bytes.NewBuffer([]byte(testKeystoreConfiguration)))
		require.NoError(t, err)

		op := New(keystore.NewMockProvider())
		handler := getHandler(t, op, createKeystoreEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusCreated, rr.Code)
		require.NotEmpty(t, rr.Header().Get("Location"))
	})
	t.Run("Failed to read the request body", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, createKeystoreEndpoint, errReader(0))

		op := New(keystore.NewMockProvider())
		handler := getHandler(t, op, createKeystoreEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), fmt.Sprintf(readRequestFailure, ""))
	})
	t.Run("Received invalid keystore configuration", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, "", bytes.NewBuffer([]byte("")))
		require.NoError(t, err)

		op := New(keystore.NewMockProvider())
		handler := getHandler(t, op, createKeystoreEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), fmt.Sprintf(receivedInvalidConfiguration, ""))
	})
	t.Run("Failed to create a keystore", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, "", bytes.NewBuffer([]byte(testKeystoreConfiguration)))
		require.NoError(t, err)

		provider := keystore.NewMockProvider()
		provider.CreateErr = errors.New("create keystore failed")

		op := New(provider)
		handler := getHandler(t, op, createKeystoreEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), fmt.Sprintf(createKeystoreFailure, ""))
	})
}

func getHandler(t *testing.T, op *Operation, pathToLookup, methodToLookup string) Handler {
	return getHandlerWithError(t, op, pathToLookup, methodToLookup)
}

func getHandlerWithError(t *testing.T, op *Operation, pathToLookup, methodToLookup string) Handler {
	return handlerLookup(t, op, pathToLookup, methodToLookup)
}

func handlerLookup(t *testing.T, op *Operation, pathToLookup, methodToLookup string) Handler {
	handlers := op.GetRESTHandlers()
	require.NotEmpty(t, handlers)

	for _, h := range handlers {
		if h.Path() == pathToLookup && h.Method() == methodToLookup {
			return h
		}
	}

	require.Fail(t, "unable to find handler")

	return nil
}
