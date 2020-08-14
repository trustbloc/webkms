/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/signature"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/hub-kms/pkg/keystore"
	"github.com/trustbloc/hub-kms/pkg/kms"
)

const (
	validCreateKeystoreReq = `{
	  "controller": "did:example:123456789"
	}`

	validCreateKeyReq = `{
	  "keyType": "ED25519"
	}`

	validSignReq = `{
	  "message": "message to sign"
	}`

	validVerifyReq = `{
	  "signature": "c2lnbmF0dXJl",
	  "message": "message to sign"
	}`

	badEncodedSignatureVerifyReq = `{
	  "signature": "!",
	  "message": "message to sign"
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

	t.Run("Received bad request: EOF", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, "", bytes.NewBuffer([]byte("")))
		require.NoError(t, err)

		op := New(NewMockProvider())
		handler := getHandler(t, op, keystoresEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), fmt.Sprintf(receivedBadRequest, "EOF"))
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

		req = mux.SetURLVars(req, map[string]string{
			"keystoreID": testKeystoreID,
		})

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

	t.Run("Received bad request: EOF", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, "", bytes.NewBuffer([]byte("")))
		require.NoError(t, err)

		op := New(NewMockProvider())
		handler := getHandler(t, op, keysEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), fmt.Sprintf(receivedBadRequest, "EOF"))
	})

	t.Run("Failed to create a kms provider: open store", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, "", bytes.NewBuffer([]byte(validCreateKeyReq)))
		require.NoError(t, err)

		provider := NewMockProvider()
		provider.MockStorage.ErrOpenStoreHandle = errors.New("open store error")
		op := New(provider)
		handler := getHandler(t, op, keysEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), strings.TrimSuffix(createKMSProviderFailure, "%s"))
	})

	t.Run("Failed to create a kms provider: kms creator error", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, "", bytes.NewBuffer([]byte(validCreateKeyReq)))
		require.NoError(t, err)

		provider := NewMockProvider()
		provider.KMSCreatorErr = errors.New("kms creator error")
		op := New(provider)
		handler := getHandler(t, op, keysEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), strings.TrimSuffix(createKMSProviderFailure, "%s"))
	})

	t.Run("Failed to create a key: create key error", func(t *testing.T) {
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

func TestSignHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, "", bytes.NewBuffer([]byte(validSignReq)))
		require.NoError(t, err)

		req = mux.SetURLVars(req, map[string]string{
			"keystoreID": testKeystoreID,
			"keyID":      testKeyID,
		})

		provider := NewMockProvider()
		provider.MockStorage.Store.Store[testKeystoreID] = keystoreBytes(t)
		provider.MockCrypto.SignValue = []byte("signature")

		op := New(provider)
		handler := getHandler(t, op, signEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusOK, rr.Code)
		require.Equal(t, base64.URLEncoding.EncodeToString([]byte("signature")), rr.Body.String())
	})

	t.Run("Received bad request: EOF", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, "", bytes.NewBuffer([]byte("")))
		require.NoError(t, err)

		op := New(NewMockProvider())
		handler := getHandler(t, op, signEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), fmt.Sprintf(receivedBadRequest, "EOF"))
	})

	t.Run("Failed to create a kms provider: open store", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, "", bytes.NewBuffer([]byte(validSignReq)))
		require.NoError(t, err)

		provider := NewMockProvider()
		provider.MockStorage.ErrOpenStoreHandle = errors.New("open store error")
		op := New(provider)
		handler := getHandler(t, op, signEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), strings.TrimSuffix(createKMSProviderFailure, "%s"))
	})

	t.Run("Failed to create a kms provider: kms creator error", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, "", bytes.NewBuffer([]byte(validSignReq)))
		require.NoError(t, err)

		provider := NewMockProvider()
		provider.KMSCreatorErr = errors.New("kms creator error")
		op := New(provider)
		handler := getHandler(t, op, signEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), strings.TrimSuffix(createKMSProviderFailure, "%s"))
	})

	t.Run("Failed to sign a message: sign error", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, "", bytes.NewBuffer([]byte(validCreateKeyReq)))
		require.NoError(t, err)

		req = mux.SetURLVars(req, map[string]string{
			"keystoreID": testKeystoreID,
			"keyID":      testKeyID,
		})

		provider := NewMockProvider()
		provider.MockStorage.Store.Store[testKeystoreID] = keystoreBytes(t)
		provider.MockCrypto.SignErr = errors.New("sign error")
		op := New(provider)
		handler := getHandler(t, op, signEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), strings.TrimSuffix(signMessageFailure, "%s"))
	})
}

func TestVerifyHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, "", bytes.NewBuffer([]byte(validVerifyReq)))
		require.NoError(t, err)

		req = mux.SetURLVars(req, map[string]string{
			"keystoreID": testKeystoreID,
			"keyID":      testKeyID,
		})

		kh, err := keyset.NewHandle(signature.ED25519KeyTemplate())
		require.NoError(t, err)

		provider := NewMockProvider()
		provider.MockStorage.Store.Store[testKeystoreID] = keystoreBytes(t)
		provider.MockKMS.GetKeyValue = kh

		op := New(provider)
		handler := getHandler(t, op, verifyEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Success: invalid signature", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, "", bytes.NewBuffer([]byte(validVerifyReq)))
		require.NoError(t, err)

		req = mux.SetURLVars(req, map[string]string{
			"keystoreID": testKeystoreID,
			"keyID":      testKeyID,
		})

		kh, err := keyset.NewHandle(signature.ED25519KeyTemplate())
		require.NoError(t, err)

		provider := NewMockProvider()
		provider.MockStorage.Store.Store[testKeystoreID] = keystoreBytes(t)
		provider.MockKMS.GetKeyValue = kh
		provider.MockCrypto.VerifyErr = errors.New("verify msg: invalid signature")

		op := New(provider)
		handler := getHandler(t, op, verifyEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusOK, rr.Code)
		require.Equal(t, rr.Body.String(), kms.ErrInvalidSignature.Error())
	})

	t.Run("Received bad request: EOF", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, "", bytes.NewBuffer([]byte("")))
		require.NoError(t, err)

		op := New(NewMockProvider())
		handler := getHandler(t, op, verifyEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), fmt.Sprintf(receivedBadRequest, "EOF"))
	})

	t.Run("Received bad request: bad encoded signature", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, "", bytes.NewBuffer([]byte(badEncodedSignatureVerifyReq)))
		require.NoError(t, err)

		op := New(NewMockProvider())
		handler := getHandler(t, op, verifyEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), strings.TrimSuffix(receivedBadRequest, "%s"))
	})

	t.Run("Failed to create a kms provider: open store", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, "", bytes.NewBuffer([]byte(validVerifyReq)))
		require.NoError(t, err)

		provider := NewMockProvider()
		provider.MockStorage.ErrOpenStoreHandle = errors.New("open store error")
		op := New(provider)
		handler := getHandler(t, op, verifyEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), strings.TrimSuffix(createKMSProviderFailure, "%s"))
	})

	t.Run("Failed to create a kms provider: kms creator error", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, "", bytes.NewBuffer([]byte(validVerifyReq)))
		require.NoError(t, err)

		provider := NewMockProvider()
		provider.KMSCreatorErr = errors.New("kms creator error")
		op := New(provider)
		handler := getHandler(t, op, verifyEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), strings.TrimSuffix(createKMSProviderFailure, "%s"))
	})

	t.Run("Failed to verify a message: verify error", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, "", bytes.NewBuffer([]byte(validVerifyReq)))
		require.NoError(t, err)

		req = mux.SetURLVars(req, map[string]string{
			"keystoreID": testKeystoreID,
			"keyID":      testKeyID,
		})

		kh, err := keyset.NewHandle(signature.ED25519KeyTemplate())
		require.NoError(t, err)

		provider := NewMockProvider()
		provider.MockStorage.Store.Store[testKeystoreID] = keystoreBytes(t)
		provider.MockKMS.GetKeyValue = kh
		provider.MockCrypto.VerifyErr = errors.New("verify error")

		op := New(provider)
		handler := getHandler(t, op, verifyEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), strings.TrimSuffix(verifyMessageFailure, "%s"))
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
		KeyIDs:     []string{testKeyID},
	}

	bytes, err := json.Marshal(testKeystore)
	require.NoError(t, err)

	return bytes
}
