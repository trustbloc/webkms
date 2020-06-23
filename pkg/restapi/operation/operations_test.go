/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/storage"
	"github.com/trustbloc/edge-core/pkg/storage/mockstore"
)

const (
	validConfiguration = `{
	  "controller": "did:example:123456789"
	}`

	missingControllerConfiguration = `{
	  "sequence": 0
	}`

	invalidStartingSequenceConfiguration = `{
	  "controller": "did:example:123456789",
	  "sequence": 1
	}`
)

// errReader returns an error when reading its body
type errReader int

func (errReader) Read(_ []byte) (n int, err error) {
	return 0, errors.New("read error")
}

func TestNew(t *testing.T) {
	srv := New(mockstore.NewMockStoreProvider())
	require.NotNil(t, srv)
}

func TestCreateKeystoreHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, "", bytes.NewBuffer([]byte(validConfiguration)))
		require.NoError(t, err)

		provider := mockstore.NewMockStoreProvider()
		op := New(provider)
		handler := getHandler(t, op, createKeystoreEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusCreated, rr.Code)
		require.NotEmpty(t, rr.Header().Get("Location"))
	})
	t.Run("Failed to read the request body", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, createKeystoreEndpoint, errReader(0))

		op := New(mockstore.NewMockStoreProvider())
		handler := getHandler(t, op, createKeystoreEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), strings.TrimSuffix(readRequestFailure, "%s"))
	})
	t.Run("Received invalid keystore configuration", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, "", bytes.NewBuffer([]byte("")))
		require.NoError(t, err)

		op := New(mockstore.NewMockStoreProvider())
		handler := getHandler(t, op, createKeystoreEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), strings.TrimSuffix(receivedInvalidConfiguration, "%s"))
	})
	t.Run("Received invalid keystore configuration: invalid starting sequence", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, "", bytes.NewBuffer([]byte(invalidStartingSequenceConfiguration)))
		require.NoError(t, err)

		op := New(mockstore.NewMockStoreProvider())
		handler := getHandler(t, op, createKeystoreEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), strings.TrimSuffix(receivedInvalidConfiguration, "%s"))
	})
	t.Run("Received invalid keystore configuration: missing controller", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, "", bytes.NewBuffer([]byte(missingControllerConfiguration)))
		require.NoError(t, err)

		op := New(mockstore.NewMockStoreProvider())
		handler := getHandler(t, op, createKeystoreEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), strings.TrimSuffix(receivedInvalidConfiguration, "%s"))
	})
	t.Run("Failed to create a keystore", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, "", bytes.NewBuffer([]byte(validConfiguration)))
		require.NoError(t, err)

		provider := mockstore.NewMockStoreProvider()
		provider.ErrCreateStore = errors.New("create keystore failed")

		op := New(provider)
		handler := getHandler(t, op, createKeystoreEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), strings.TrimSuffix(createKeystoreFailure, "%s"))
	})
	t.Run("Failed to create a keystore: duplicate keystore", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, "", bytes.NewBuffer([]byte(validConfiguration)))
		require.NoError(t, err)

		provider := mockstore.NewMockStoreProvider()
		provider.ErrCreateStore = storage.ErrDuplicateStore

		op := New(provider)
		handler := getHandler(t, op, createKeystoreEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusConflict, rr.Code)
		require.Contains(t, rr.Body.String(), strings.TrimSuffix(createKeystoreFailure, "%s"))
	})
	t.Run("Failed to create a keystore: open store", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, "", bytes.NewBuffer([]byte(validConfiguration)))
		require.NoError(t, err)

		provider := mockstore.NewMockStoreProvider()
		provider.ErrOpenStoreHandle = errors.New("open store")

		op := New(provider)
		handler := getHandler(t, op, createKeystoreEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), strings.TrimSuffix(createKeystoreFailure, "%s"))
	})
	t.Run("Failed to create a keystore: store put", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, "", bytes.NewBuffer([]byte(validConfiguration)))
		require.NoError(t, err)

		provider := mockstore.NewMockStoreProvider()
		provider.Store.ErrPut = errors.New("store put")

		op := New(provider)
		handler := getHandler(t, op, createKeystoreEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), strings.TrimSuffix(createKeystoreFailure, "%s"))
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
