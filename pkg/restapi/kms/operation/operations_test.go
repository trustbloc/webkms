/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/hub-kms/pkg/keystore"
)

const (
	validCreateKeystoreReq = `{
	  "controller": "did:example:123456789"
	}`

	validCreateKeyReq = `{
	  "keystoreID": "bsi5ct08vcqmquc0fn5g",
	  "keyType": "ED25519",
	  "passphrase": "p@ssphrase"
	}`

	testKeyID      = "Fm4r2iwjYnswLRZKl38W"
	testKeystoreID = "bsi5ct08vcqmquc0fn5g"
	testController = "did:example:123456789"
)

// errReader returns an error when reading its body
type errReader int

func (errReader) Read(_ []byte) (n int, err error) {
	return 0, errors.New("read error")
}

func TestNew(t *testing.T) {
	srv := New(NewMockProvider())
	require.NotNil(t, srv)
	require.NotEmpty(t, srv.handlers)
}

func TestCreateKeystoreHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, "", bytes.NewBuffer([]byte(validCreateKeystoreReq)))
		require.NoError(t, err)

		provider := NewMockProvider()
		op := New(provider)
		handler := getHandler(t, op, keystoresEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusCreated, rr.Code)
		require.NotEmpty(t, rr.Header().Get("Location"))
	})

	t.Run("Failed to read the request body", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, keystoresEndpoint, errReader(0))

		op := New(NewMockProvider())
		handler := getHandler(t, op, keystoresEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), strings.TrimSuffix(readRequestFailure, "%s"))
	})

	t.Run("Received bad request", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, "", bytes.NewBuffer([]byte("")))
		require.NoError(t, err)

		op := New(NewMockProvider())
		handler := getHandler(t, op, keystoresEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), strings.TrimSuffix(receivedBadRequest, "%s"))
	})

	t.Run("Failed to create storage for a keystore", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, "", bytes.NewBuffer([]byte(validCreateKeystoreReq)))
		require.NoError(t, err)

		provider := NewMockProvider()
		provider.MockStorage.ErrCreateStore = errors.New("create keystore error")

		op := New(provider)
		handler := getHandler(t, op, keystoresEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), strings.TrimSuffix(createKeystoreFailure, "%s"))
	})

	t.Run("Failed to create a keystore", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, "", bytes.NewBuffer([]byte(validCreateKeystoreReq)))
		require.NoError(t, err)

		provider := NewMockProvider()
		// TODO: Use keystore.Service mock to set an error (part of https://github.com/trustbloc/hub-kms/issues/29)
		provider.MockStorage.Store.ErrPut = errors.New("store put error")

		op := New(provider)
		handler := getHandler(t, op, keystoresEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), strings.TrimSuffix(createKeystoreFailure, "%s"))
	})
}

func TestCreateKeyHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, "", bytes.NewBuffer([]byte(validCreateKeyReq)))
		require.NoError(t, err)

		provider := NewMockProvider()
		provider.MockKMS.CreateKeyID = testKeyID
		provider.MockStorage.Store.Store[testKeystoreID] = keystoreBytes(t)

		op := New(provider)
		handler := getHandler(t, op, keysEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusCreated, rr.Code)
		require.NotEmpty(t, rr.Header().Get("Location"))
	})

	t.Run("Failed to read the request body", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, keysEndpoint, errReader(0))

		op := New(NewMockProvider())
		handler := getHandler(t, op, keysEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), strings.TrimSuffix(readRequestFailure, "%s"))
	})

	t.Run("Received bad request", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, "", bytes.NewBuffer([]byte("")))
		require.NoError(t, err)

		op := New(NewMockProvider())
		handler := getHandler(t, op, keysEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), strings.TrimSuffix(receivedBadRequest, "%s"))
	})

	t.Run("Failed to create a keystore provider: open store", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, "", bytes.NewBuffer([]byte(validCreateKeyReq)))
		require.NoError(t, err)

		provider := NewMockProvider()
		provider.MockStorage.ErrOpenStoreHandle = errors.New("open store error")
		op := New(provider)
		handler := getHandler(t, op, keysEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), strings.TrimSuffix(createKeystoreProviderFailure, "%s"))
	})

	t.Run("Failed to create a keystore provider: kms creator error", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, "", bytes.NewBuffer([]byte(validCreateKeyReq)))
		require.NoError(t, err)

		provider := NewMockProvider()
		provider.KMSCreatorErr = errors.New("kms creator error")
		op := New(provider)
		handler := getHandler(t, op, keysEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), strings.TrimSuffix(createKeystoreProviderFailure, "%s"))
	})

	t.Run("Failed to create a key: kms creator error", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, "", bytes.NewBuffer([]byte(validCreateKeyReq)))
		require.NoError(t, err)

		provider := NewMockProvider()
		provider.MockKMS.CreateKeyErr = errors.New("create key error")
		op := New(provider)
		handler := getHandler(t, op, keysEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), strings.TrimSuffix(createKeyFailure, "%s"))
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

func keystoreBytes(t *testing.T) []byte {
	t.Helper()

	testKeystore := keystore.Keystore{
		ID:         testKeystoreID,
		Controller: testController,
	}

	bytes, err := json.Marshal(testKeystore)
	require.NoError(t, err)

	return bytes
}
