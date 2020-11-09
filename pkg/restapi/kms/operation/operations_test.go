/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	mockoperation "github.com/trustbloc/hub-kms/pkg/internal/mock/operation"
	"github.com/trustbloc/hub-kms/pkg/keystore"
	"github.com/trustbloc/hub-kms/pkg/restapi/kms/operation"
)

const (
	testKeystoreID = "bsi5ct08vcqmquc0fn5g"
	testKeyID      = "Fm4r2iwjYnswLRZKl38W"
	testController = "did:example:123456789"
)

const (
	keystoresEndpoint  = "/kms/keystores"
	keysEndpoint       = "/kms/keystores/{keystoreID}/keys"
	signEndpoint       = "/kms/keystores/{keystoreID}/keys/{keyID}/sign"
	verifyEndpoint     = "/kms/keystores/{keystoreID}/keys/{keyID}/verify"
	encryptEndpoint    = "/kms/keystores/{keystoreID}/keys/{keyID}/encrypt"
	decryptEndpoint    = "/kms/keystores/{keystoreID}/keys/{keyID}/decrypt"
	computeMACEndpoint = "/kms/keystores/{keystoreID}/keys/{keyID}/computemac"
	verifyMACEndpoint  = "/kms/keystores/{keystoreID}/keys/{keyID}/verifymac"
)

const (
	createKeystoreReqFormat = `{
	  "controller": "%s"
	}`

	createKeyReqFormat = `{
	  "keyType": "%s"
	}`

	signReqFormat = `{
	  "message": "%s"
	}`

	verifyReqFormat = `{
	  "signature": "%s",
	  "message": "%s"
	}`

	encryptReqFormat = `{
	  "message": "%s",
	  "aad": "%s"
	}`

	decryptReqFormat = `{
	  "cipherText": "%s",
	  "aad": "%s",
	  "nonce": "%s"
	}`

	computeMACReqFormat = `{
	  "data": "%s"
	}`

	verifyMACReqFormat = `{
	  "mac": "%s",
	  "data": "%s"
	}`
)

func TestNew(t *testing.T) {
	op := operation.New(mockoperation.NewMockProvider())
	require.NotNil(t, op)
}

func TestCreateKeystoreHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider := mockoperation.NewMockProvider()
		provider.MockKeystoreService.CreateKeystore = &keystore.Keystore{ID: testKeystoreID}
		op := operation.New(provider)
		handler := getHandler(t, op, keystoresEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildCreateKeystoreReq(t, testController))

		require.Equal(t, http.StatusCreated, rr.Code)
		require.NotEmpty(t, rr.Header().Get("Location"))
	})

	t.Run("Received bad request", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", bytes.NewBuffer([]byte("")))
		require.NoError(t, err)

		op := operation.New(mockoperation.NewMockProvider())
		handler := getHandler(t, op, keystoresEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request: EOF")
	})

	t.Run("Failed to create a keystore", func(t *testing.T) {
		provider := mockoperation.NewMockProvider()
		provider.MockKeystoreService.CreateErr = errors.New("create keystore error")

		op := operation.New(provider)
		handler := getHandler(t, op, keystoresEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildCreateKeystoreReq(t, testController))

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to create a keystore: create keystore error")
	})
}

func TestCreateKeyHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider := mockoperation.NewMockProvider()

		op := operation.New(provider)
		handler := getHandler(t, op, keysEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildCreateKeyReq(t))

		require.Equal(t, http.StatusCreated, rr.Code)
		require.NotEmpty(t, rr.Header().Get("Location"))
	})

	t.Run("Received bad request", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", bytes.NewBuffer([]byte("")))
		require.NoError(t, err)

		op := operation.New(mockoperation.NewMockProvider())
		handler := getHandler(t, op, keysEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request: EOF")
	})

	t.Run("Failed to create a KMS service", func(t *testing.T) {
		provider := mockoperation.NewMockProvider()
		provider.KMSServiceCreatorErr = errors.New("kms service creator error")
		op := operation.New(provider)
		handler := getHandler(t, op, keysEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildCreateKeyReq(t))

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to create a KMS service: kms service creator error")
	})

	t.Run("Failed to create a key", func(t *testing.T) {
		provider := mockoperation.NewMockProvider()
		provider.MockKMSService.CreateKeyErr = errors.New("create key error")
		op := operation.New(provider)
		handler := getHandler(t, op, keysEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildCreateKeyReq(t))

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to create a key: create key error")
	})
}

func TestSignHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider := mockoperation.NewMockProvider()
		provider.MockKMSService.SignValue = []byte("signature")

		op := operation.New(provider)
		handler := getHandler(t, op, signEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildSignReq(t))

		require.Equal(t, http.StatusOK, rr.Code)
		require.Contains(t, rr.Body.String(), base64.URLEncoding.EncodeToString([]byte("signature")))
	})

	t.Run("Received bad request", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", bytes.NewBuffer([]byte("")))
		require.NoError(t, err)

		op := operation.New(mockoperation.NewMockProvider())
		handler := getHandler(t, op, signEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request: EOF")
	})

	t.Run("Failed to create a KMS service", func(t *testing.T) {
		provider := mockoperation.NewMockProvider()
		provider.KMSServiceCreatorErr = errors.New("kms service creator error")
		op := operation.New(provider)
		handler := getHandler(t, op, signEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildSignReq(t))

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to create a KMS service: kms service creator error")
	})

	t.Run("Failed to sign a message", func(t *testing.T) {
		provider := mockoperation.NewMockProvider()
		provider.MockKMSService.SignErr = errors.New("sign error")
		op := operation.New(provider)
		handler := getHandler(t, op, signEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildSignReq(t))

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to sign a message: sign error")
	})
}

func TestVerifyHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		op := operation.New(mockoperation.NewMockProvider())
		handler := getHandler(t, op, verifyEndpoint, http.MethodPost)

		sig := base64.URLEncoding.EncodeToString([]byte("test signature"))
		req := buildVerifyReq(t, sig)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Received bad request: EOF", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", bytes.NewBuffer([]byte("")))
		require.NoError(t, err)

		op := operation.New(mockoperation.NewMockProvider())
		handler := getHandler(t, op, verifyEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request: EOF")
	})

	t.Run("Received bad request: bad encoded signature", func(t *testing.T) {
		op := operation.New(mockoperation.NewMockProvider())
		handler := getHandler(t, op, verifyEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildVerifyReq(t, "!signature"))

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request")
	})

	t.Run("Failed to create a KMS service", func(t *testing.T) {
		provider := mockoperation.NewMockProvider()
		provider.KMSServiceCreatorErr = errors.New("kms service creator error")
		op := operation.New(provider)
		handler := getHandler(t, op, verifyEndpoint, http.MethodPost)

		sig := base64.URLEncoding.EncodeToString([]byte("test signature"))
		req := buildVerifyReq(t, sig)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to create a KMS service: kms service creator error")
	})

	t.Run("Failed to verify a message: verify error", func(t *testing.T) {
		provider := mockoperation.NewMockProvider()
		provider.MockKMSService.VerifyErr = errors.New("verify error")
		op := operation.New(provider)
		handler := getHandler(t, op, verifyEndpoint, http.MethodPost)

		sig := base64.URLEncoding.EncodeToString([]byte("test signature"))
		req := buildVerifyReq(t, sig)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to verify a message: verify error")
	})
}

func TestEncryptHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider := mockoperation.NewMockProvider()
		provider.MockKMSService.EncryptValue = []byte("cipher text")
		op := operation.New(provider)
		handler := getHandler(t, op, encryptEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildEncryptReq(t))

		require.Equal(t, http.StatusOK, rr.Code)
		require.Contains(t, rr.Body.String(), base64.URLEncoding.EncodeToString([]byte("cipher text")))
	})

	t.Run("Received bad request", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", bytes.NewBuffer([]byte("")))
		require.NoError(t, err)

		op := operation.New(mockoperation.NewMockProvider())
		handler := getHandler(t, op, encryptEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request: EOF")
	})

	t.Run("Failed to create a KMS service", func(t *testing.T) {
		provider := mockoperation.NewMockProvider()
		provider.KMSServiceCreatorErr = errors.New("kms service creator error")
		op := operation.New(provider)
		handler := getHandler(t, op, encryptEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildEncryptReq(t))

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to create a KMS service: kms service creator error")
	})

	t.Run("Failed to encrypt a message", func(t *testing.T) {
		provider := mockoperation.NewMockProvider()
		provider.MockKMSService.EncryptErr = errors.New("encrypt error")
		op := operation.New(provider)
		handler := getHandler(t, op, encryptEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildEncryptReq(t))

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to encrypt a message: encrypt error")
	})
}

func TestDecryptHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider := mockoperation.NewMockProvider()
		provider.MockKMSService.DecryptValue = []byte("plain text")
		op := operation.New(provider)
		handler := getHandler(t, op, decryptEndpoint, http.MethodPost)

		cipherText := base64.URLEncoding.EncodeToString([]byte("test cipher text"))
		nonce := base64.URLEncoding.EncodeToString([]byte("test nonce"))
		req := buildDecryptReq(t, cipherText, nonce)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusOK, rr.Code)
		require.Contains(t, rr.Body.String(), "plain text")
	})

	t.Run("Received bad request: EOF", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", bytes.NewBuffer([]byte("")))
		require.NoError(t, err)

		op := operation.New(mockoperation.NewMockProvider())
		handler := getHandler(t, op, decryptEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request: EOF")
	})

	t.Run("Received bad request: bad encoded cipher text", func(t *testing.T) {
		op := operation.New(mockoperation.NewMockProvider())
		handler := getHandler(t, op, decryptEndpoint, http.MethodPost)

		nonce := base64.URLEncoding.EncodeToString([]byte("test nonce"))
		req := buildDecryptReq(t, "!cipher", nonce)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request")
	})

	t.Run("Received bad request: bad encoded nonce", func(t *testing.T) {
		op := operation.New(mockoperation.NewMockProvider())
		handler := getHandler(t, op, decryptEndpoint, http.MethodPost)

		cipherText := base64.URLEncoding.EncodeToString([]byte("test cipher text"))
		req := buildDecryptReq(t, cipherText, "!nonce")

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request")
	})

	t.Run("Failed to create a KMS service", func(t *testing.T) {
		provider := mockoperation.NewMockProvider()
		provider.KMSServiceCreatorErr = errors.New("kms service creator error")
		op := operation.New(provider)
		handler := getHandler(t, op, decryptEndpoint, http.MethodPost)

		cipherText := base64.URLEncoding.EncodeToString([]byte("test cipher text"))
		nonce := base64.URLEncoding.EncodeToString([]byte("test nonce"))
		req := buildDecryptReq(t, cipherText, nonce)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to create a KMS service: kms service creator error")
	})

	t.Run("Failed to decrypt a message", func(t *testing.T) {
		provider := mockoperation.NewMockProvider()
		provider.MockKMSService.DecryptErr = errors.New("decrypt error")
		op := operation.New(provider)
		handler := getHandler(t, op, decryptEndpoint, http.MethodPost)

		cipherText := base64.URLEncoding.EncodeToString([]byte("test cipher text"))
		nonce := base64.URLEncoding.EncodeToString([]byte("test nonce"))
		req := buildDecryptReq(t, cipherText, nonce)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to decrypt a message: decrypt error")
	})
}

func TestComputeMACHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider := mockoperation.NewMockProvider()
		provider.MockKMSService.ComputeMACValue = []byte("mac")
		op := operation.New(provider)
		handler := getHandler(t, op, computeMACEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildComputeMACReq(t))

		require.Equal(t, http.StatusOK, rr.Code)
		require.Contains(t, rr.Body.String(), base64.URLEncoding.EncodeToString([]byte("mac")))
	})

	t.Run("Received bad request", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", bytes.NewBuffer([]byte("")))
		require.NoError(t, err)
		op := operation.New(mockoperation.NewMockProvider())
		handler := getHandler(t, op, computeMACEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request: EOF")
	})

	t.Run("Failed to create a KMS service", func(t *testing.T) {
		provider := mockoperation.NewMockProvider()
		provider.KMSServiceCreatorErr = errors.New("kms service creator error")
		op := operation.New(provider)
		handler := getHandler(t, op, computeMACEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildComputeMACReq(t))

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to create a KMS service: kms service creator error")
	})

	t.Run("Failed to compute MAC", func(t *testing.T) {
		provider := mockoperation.NewMockProvider()
		provider.MockKMSService.ComputeMACErr = errors.New("compute mac error")
		op := operation.New(provider)
		handler := getHandler(t, op, computeMACEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildComputeMACReq(t))

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to compute MAC: compute mac error")
	})
}

func TestVerifyMACHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider := mockoperation.NewMockProvider()
		provider.MockKMSService.ComputeMACValue = []byte("mac")
		op := operation.New(provider)
		handler := getHandler(t, op, verifyMACEndpoint, http.MethodPost)

		mac := base64.URLEncoding.EncodeToString([]byte("test mac"))
		req := buildVerifyMACReq(t, mac)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Received bad request: EOF", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", bytes.NewBuffer([]byte("")))
		require.NoError(t, err)
		op := operation.New(mockoperation.NewMockProvider())
		handler := getHandler(t, op, verifyMACEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request: EOF")
	})

	t.Run("Received bad request: bad encoded mac", func(t *testing.T) {
		op := operation.New(mockoperation.NewMockProvider())
		handler := getHandler(t, op, verifyMACEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildVerifyMACReq(t, "!mac"))

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request")
	})

	t.Run("Failed to create a KMS service", func(t *testing.T) {
		provider := mockoperation.NewMockProvider()
		provider.KMSServiceCreatorErr = errors.New("kms service creator error")
		op := operation.New(provider)
		handler := getHandler(t, op, verifyMACEndpoint, http.MethodPost)

		mac := base64.URLEncoding.EncodeToString([]byte("test mac"))
		req := buildVerifyMACReq(t, mac)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to create a KMS service: kms service creator error")
	})

	t.Run("Failed to verify MAC", func(t *testing.T) {
		provider := mockoperation.NewMockProvider()
		provider.MockKMSService.VerifyMACErr = errors.New("verify mac error")
		op := operation.New(provider)
		handler := getHandler(t, op, verifyMACEndpoint, http.MethodPost)

		mac := base64.URLEncoding.EncodeToString([]byte("test mac"))
		req := buildVerifyMACReq(t, mac)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to verify MAC: verify mac error")
	})
}

type failingResponseWriter struct {
	*httptest.ResponseRecorder
}

func (failingResponseWriter) Write(_ []byte) (int, error) {
	return 0, errors.New("write error")
}

func TestFailToWriteResponse(t *testing.T) {
	provider := mockoperation.NewMockProvider()
	provider.MockKMSService.SignValue = []byte("signature")

	op := operation.New(provider)
	handler := getHandler(t, op, signEndpoint, http.MethodPost)
	req := buildSignReq(t)

	rr := failingResponseWriter{httptest.NewRecorder()}
	handler.Handle().ServeHTTP(rr, req)

	require.Empty(t, rr.Body.String())
	require.Contains(t, provider.MockLogger.ErrorLogContents, "Unable to send a response")
}

func TestFailToWriteErrorResponse(t *testing.T) {
	provider := mockoperation.NewMockProvider()
	provider.MockKMSService.CreateKeyErr = errors.New("create key error")

	op := operation.New(provider)
	handler := getHandler(t, op, keysEndpoint, http.MethodPost)
	req := buildCreateKeyReq(t)

	rr := failingResponseWriter{httptest.NewRecorder()}
	handler.Handle().ServeHTTP(rr, req)

	require.Empty(t, rr.Body.String())
	require.Contains(t, provider.MockLogger.ErrorLogContents, "Unable to send an error message")
}

func getHandler(t *testing.T, op *operation.Operation, pathToLookup, methodToLookup string) operation.Handler {
	return getHandlerWithError(t, op, pathToLookup, methodToLookup)
}

func getHandlerWithError(t *testing.T, op *operation.Operation, pathToLookup, methodToLookup string) operation.Handler {
	return handlerLookup(t, op, pathToLookup, methodToLookup)
}

func handlerLookup(t *testing.T, op *operation.Operation, pathToLookup, methodToLookup string) operation.Handler {
	t.Helper()

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

func buildCreateKeystoreReq(t *testing.T, controller string) *http.Request {
	t.Helper()

	payload := fmt.Sprintf(createKeystoreReqFormat, controller)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", bytes.NewBuffer([]byte(payload)))
	require.NoError(t, err)

	return req
}

func buildCreateKeyReq(t *testing.T) *http.Request {
	t.Helper()

	payload := fmt.Sprintf(createKeyReqFormat, "ED25519")
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", bytes.NewBuffer([]byte(payload)))
	require.NoError(t, err)

	req = mux.SetURLVars(req, map[string]string{
		"keystoreID": testKeystoreID,
	})

	return req
}

func buildSignReq(t *testing.T) *http.Request {
	t.Helper()

	payload := fmt.Sprintf(signReqFormat, "test message")
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", bytes.NewBuffer([]byte(payload)))
	require.NoError(t, err)

	req = mux.SetURLVars(req, map[string]string{
		"keystoreID": testKeystoreID,
		"keyID":      testKeyID,
	})

	return req
}

func buildVerifyReq(t *testing.T, sig string) *http.Request {
	t.Helper()

	payload := fmt.Sprintf(verifyReqFormat, sig, "test message")
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", bytes.NewBuffer([]byte(payload)))
	require.NoError(t, err)

	req = mux.SetURLVars(req, map[string]string{
		"keystoreID": testKeystoreID,
		"keyID":      testKeyID,
	})

	return req
}

func buildEncryptReq(t *testing.T) *http.Request {
	t.Helper()

	payload := fmt.Sprintf(encryptReqFormat, "test message", "additional data")
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", bytes.NewBuffer([]byte(payload)))
	require.NoError(t, err)

	req = mux.SetURLVars(req, map[string]string{
		"keystoreID": testKeystoreID,
		"keyID":      testKeyID,
	})

	return req
}

func buildDecryptReq(t *testing.T, cipherText, nonce string) *http.Request {
	t.Helper()

	payload := fmt.Sprintf(decryptReqFormat, cipherText, "additional data", nonce)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", bytes.NewBuffer([]byte(payload)))
	require.NoError(t, err)

	req = mux.SetURLVars(req, map[string]string{
		"keystoreID": testKeystoreID,
		"keyID":      testKeyID,
	})

	return req
}

func buildComputeMACReq(t *testing.T) *http.Request {
	t.Helper()

	payload := fmt.Sprintf(computeMACReqFormat, "test data")
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", bytes.NewBuffer([]byte(payload)))
	require.NoError(t, err)

	req = mux.SetURLVars(req, map[string]string{
		"keystoreID": testKeystoreID,
		"keyID":      testKeyID,
	})

	return req
}

func buildVerifyMACReq(t *testing.T, mac string) *http.Request {
	t.Helper()

	payload := fmt.Sprintf(verifyMACReqFormat, mac, "test data")
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", bytes.NewBuffer([]byte(payload)))
	require.NoError(t, err)

	req = mux.SetURLVars(req, map[string]string{
		"keystoreID": testKeystoreID,
		"keyID":      testKeyID,
	})

	return req
}
