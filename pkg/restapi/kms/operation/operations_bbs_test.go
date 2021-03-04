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

	"github.com/trustbloc/kms/pkg/internal/mock/keystore"
	mockkms "github.com/trustbloc/kms/pkg/internal/mock/kms"
)

const (
	signMultiEndpoint   = "/keystores/{keystoreID}/keys/{keyID}/signmulti"
	verifyMultiEndpoint = "/keystores/{keystoreID}/keys/{keyID}/verifymulti"
	deriveProofEndpoint = "/keystores/{keystoreID}/keys/{keyID}/deriveproof"
	verifyProofEndpoint = "/keystores/{keystoreID}/keys/{keyID}/verifyproof"
)

const (
	signMultiReqFormat = `{
	  "messages": ["%s","%s"]
	}`

	verifyMultiReqFormat = `{
	  "signature": "%s",
	  "messages": ["%s","%s"]
	}`

	deriveProofReqFormat = `{
	  "messages": ["%s","%s"],
	  "signature": "%s",
	  "nonce": "%s",
	  "revealedIndexes": [0]
	}`

	verifyProofReqFormat = `{
	  "messages": ["%s"],
	  "proof": "%s",
	  "nonce": "%s"
	}`
)

func TestSignMultiHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		svc := mockKMSService()
		svc.BBSSignValue = []byte("signature")

		op := newOperation(t, newConfig(withKMSService(svc)))
		handler := getHandler(t, op, signMultiEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildSignMultiReq(t, base64.URLEncoding.EncodeToString([]byte("message 1")),
			base64.URLEncoding.EncodeToString([]byte("message 2"))))

		require.Equal(t, http.StatusOK, rr.Code)
		require.Contains(t, rr.Body.String(), base64.URLEncoding.EncodeToString([]byte("signature")))
	})

	t.Run("Received bad request: EOF", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", bytes.NewBuffer([]byte("")))
		require.NoError(t, err)

		op := newOperation(t, newConfig())
		handler := getHandler(t, op, signMultiEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request: EOF")
	})

	t.Run("Received bad request: bad encoded message", func(t *testing.T) {
		op := newOperation(t, newConfig())
		handler := getHandler(t, op, signMultiEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildSignMultiReq(t, "!message",
			base64.URLEncoding.EncodeToString([]byte("message 2"))))

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request")
	})

	t.Run("Failed to resolve a keystore", func(t *testing.T) {
		svc := &mockkms.MockService{ResolveKeystoreErr: errors.New("resolve keystore error")}

		op := newOperation(t, newConfig(withKMSService(svc)))
		handler := getHandler(t, op, signMultiEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildSignMultiReq(t, base64.URLEncoding.EncodeToString([]byte("message 1")),
			base64.URLEncoding.EncodeToString([]byte("message 2"))))

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to resolve a keystore: resolve keystore error")
	})

	t.Run("Failed to get key handle", func(t *testing.T) {
		svc := mockKMSService()
		svc.ResolveKeystoreValue = &keystore.MockKeystore{GetKeyHandleErr: errors.New("get key handle error")}

		op := newOperation(t, newConfig(withKMSService(svc)))
		handler := getHandler(t, op, signMultiEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildSignMultiReq(t, base64.URLEncoding.EncodeToString([]byte("message 1")),
			base64.URLEncoding.EncodeToString([]byte("message 2"))))

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to sign messages: get key handle error")
	})

	t.Run("Failed to sign messages", func(t *testing.T) {
		svc := mockKMSService()
		svc.BBSSignErr = errors.New("sign error")

		op := newOperation(t, newConfig(withKMSService(svc)))
		handler := getHandler(t, op, signMultiEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildSignMultiReq(t, base64.URLEncoding.EncodeToString([]byte("message 1")),
			base64.URLEncoding.EncodeToString([]byte("message 2"))))

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to sign messages: sign error")
	})
}

func TestVerifyMultiHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		op := newOperation(t, newConfig())
		handler := getHandler(t, op, verifyMultiEndpoint, http.MethodPost)

		sig := base64.URLEncoding.EncodeToString([]byte("signature"))
		req := buildVerifyMultiReq(t, sig, base64.URLEncoding.EncodeToString([]byte("message 1")),
			base64.URLEncoding.EncodeToString([]byte("message 2")))

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Received bad request: EOF", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", bytes.NewBuffer([]byte("")))
		require.NoError(t, err)

		op := newOperation(t, newConfig())
		handler := getHandler(t, op, verifyMultiEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request: EOF")
	})

	t.Run("Received bad request: bad encoded signature", func(t *testing.T) {
		op := newOperation(t, newConfig())
		handler := getHandler(t, op, verifyMultiEndpoint, http.MethodPost)

		req := buildVerifyMultiReq(t, "!signature", base64.URLEncoding.EncodeToString([]byte("message 1")),
			base64.URLEncoding.EncodeToString([]byte("message 2")))

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request")
	})

	t.Run("Received bad request: bad encoded message", func(t *testing.T) {
		op := newOperation(t, newConfig())
		handler := getHandler(t, op, verifyMultiEndpoint, http.MethodPost)

		sig := base64.URLEncoding.EncodeToString([]byte("signature"))
		req := buildVerifyMultiReq(t, sig, "!message", base64.URLEncoding.EncodeToString([]byte("message 2")))

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request")
	})

	t.Run("Failed to resolve a keystore", func(t *testing.T) {
		svc := &mockkms.MockService{ResolveKeystoreErr: errors.New("resolve keystore error")}

		op := newOperation(t, newConfig(withKMSService(svc)))
		handler := getHandler(t, op, verifyMultiEndpoint, http.MethodPost)

		sig := base64.URLEncoding.EncodeToString([]byte("signature"))
		req := buildVerifyMultiReq(t, sig, base64.URLEncoding.EncodeToString([]byte("message 1")),
			base64.URLEncoding.EncodeToString([]byte("message 2")))

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to resolve a keystore: resolve keystore error")
	})

	t.Run("Failed to get key handle", func(t *testing.T) {
		svc := mockKMSService()
		svc.ResolveKeystoreValue = &keystore.MockKeystore{GetKeyHandleErr: errors.New("get key handle error")}

		op := newOperation(t, newConfig(withKMSService(svc)))
		handler := getHandler(t, op, verifyMultiEndpoint, http.MethodPost)

		sig := base64.URLEncoding.EncodeToString([]byte("signature"))
		req := buildVerifyMultiReq(t, sig, base64.URLEncoding.EncodeToString([]byte("message 1")),
			base64.URLEncoding.EncodeToString([]byte("message 2")))

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to verify messages: get key handle error")
	})

	t.Run("Failed to verify a message: verify error", func(t *testing.T) {
		svc := mockKMSService()
		svc.BBSVerifyErr = errors.New("verify error")

		op := newOperation(t, newConfig(withKMSService(svc)))
		handler := getHandler(t, op, verifyMultiEndpoint, http.MethodPost)

		sig := base64.URLEncoding.EncodeToString([]byte("test signature"))
		req := buildVerifyMultiReq(t, sig, base64.URLEncoding.EncodeToString([]byte("message 1")),
			base64.URLEncoding.EncodeToString([]byte("message 2")))

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to verify messages: verify error")
	})
}

func TestDeriveProofHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		svc := mockKMSService()
		svc.DeriveProofValue = []byte("proof")

		op := newOperation(t, newConfig(withKMSService(svc)))
		handler := getHandler(t, op, deriveProofEndpoint, http.MethodPost)

		sig := base64.URLEncoding.EncodeToString([]byte("signature"))
		non := base64.URLEncoding.EncodeToString([]byte("nonce"))

		req := buildDeriveProofReq(t, base64.URLEncoding.EncodeToString([]byte("message 1")),
			base64.URLEncoding.EncodeToString([]byte("message 2")), sig, non)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusOK, rr.Code)
		require.Contains(t, rr.Body.String(), base64.URLEncoding.EncodeToString([]byte("proof")))
	})

	t.Run("Received bad request: EOF", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", bytes.NewBuffer([]byte("")))
		require.NoError(t, err)

		op := newOperation(t, newConfig())
		handler := getHandler(t, op, deriveProofEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request: EOF")
	})

	t.Run("Received bad request: bad encoded message", func(t *testing.T) {
		op := newOperation(t, newConfig())
		handler := getHandler(t, op, deriveProofEndpoint, http.MethodPost)

		sig := base64.URLEncoding.EncodeToString([]byte("signature"))
		non := base64.URLEncoding.EncodeToString([]byte("nonce"))

		req := buildDeriveProofReq(t, "!message",
			base64.URLEncoding.EncodeToString([]byte("message 2")), sig, non)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request")
	})

	t.Run("Received bad request: bad encoded signature", func(t *testing.T) {
		op := newOperation(t, newConfig())
		handler := getHandler(t, op, deriveProofEndpoint, http.MethodPost)

		non := base64.URLEncoding.EncodeToString([]byte("nonce"))

		req := buildDeriveProofReq(t, base64.URLEncoding.EncodeToString([]byte("message 1")),
			base64.URLEncoding.EncodeToString([]byte("message 2")), "!signature", non)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request")
	})

	t.Run("Received bad request: bad encoded nonce", func(t *testing.T) {
		op := newOperation(t, newConfig())
		handler := getHandler(t, op, deriveProofEndpoint, http.MethodPost)

		sig := base64.URLEncoding.EncodeToString([]byte("signature"))

		req := buildDeriveProofReq(t, base64.URLEncoding.EncodeToString([]byte("message 1")),
			base64.URLEncoding.EncodeToString([]byte("message 2")), sig, "!nonce")

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request")
	})

	t.Run("Failed to resolve a keystore", func(t *testing.T) {
		svc := &mockkms.MockService{ResolveKeystoreErr: errors.New("resolve keystore error")}

		op := newOperation(t, newConfig(withKMSService(svc)))
		handler := getHandler(t, op, deriveProofEndpoint, http.MethodPost)

		sig := base64.URLEncoding.EncodeToString([]byte("signature"))
		non := base64.URLEncoding.EncodeToString([]byte("nonce"))

		req := buildDeriveProofReq(t, base64.URLEncoding.EncodeToString([]byte("message 1")),
			base64.URLEncoding.EncodeToString([]byte("message 2")), sig, non)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to resolve a keystore: resolve keystore error")
	})

	t.Run("Failed to get key handle", func(t *testing.T) {
		svc := mockKMSService()
		svc.ResolveKeystoreValue = &keystore.MockKeystore{GetKeyHandleErr: errors.New("get key handle error")}

		op := newOperation(t, newConfig(withKMSService(svc)))
		handler := getHandler(t, op, deriveProofEndpoint, http.MethodPost)

		sig := base64.URLEncoding.EncodeToString([]byte("signature"))
		non := base64.URLEncoding.EncodeToString([]byte("nonce"))

		req := buildDeriveProofReq(t, base64.URLEncoding.EncodeToString([]byte("message 1")),
			base64.URLEncoding.EncodeToString([]byte("message 2")), sig, non)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to derive proof: get key handle error")
	})

	t.Run("Failed to derive proof", func(t *testing.T) {
		svc := mockKMSService()
		svc.DeriveProofError = errors.New("derive proof error")

		op := newOperation(t, newConfig(withKMSService(svc)))
		handler := getHandler(t, op, deriveProofEndpoint, http.MethodPost)

		sig := base64.URLEncoding.EncodeToString([]byte("signature"))
		non := base64.URLEncoding.EncodeToString([]byte("nonce"))

		req := buildDeriveProofReq(t, base64.URLEncoding.EncodeToString([]byte("message 1")),
			base64.URLEncoding.EncodeToString([]byte("message 2")), sig, non)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to derive proof: derive proof error")
	})
}

func TestVerifyProofHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		svc := mockKMSService()
		svc.DeriveProofValue = []byte("proof")

		op := newOperation(t, newConfig(withKMSService(svc)))
		handler := getHandler(t, op, verifyProofEndpoint, http.MethodPost)

		proof := base64.URLEncoding.EncodeToString([]byte("proof"))
		nonce := base64.URLEncoding.EncodeToString([]byte("nonce"))

		req := buildVerifyProofReq(t, base64.URLEncoding.EncodeToString([]byte("message")), proof, nonce)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Received bad request: EOF", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", bytes.NewBuffer([]byte("")))
		require.NoError(t, err)

		op := newOperation(t, newConfig())
		handler := getHandler(t, op, verifyProofEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request: EOF")
	})

	t.Run("Received bad request: bad encoded message", func(t *testing.T) {
		op := newOperation(t, newConfig())
		handler := getHandler(t, op, verifyProofEndpoint, http.MethodPost)

		proof := base64.URLEncoding.EncodeToString([]byte("proof"))
		nonce := base64.URLEncoding.EncodeToString([]byte("nonce"))

		req := buildVerifyProofReq(t, "!message", proof, nonce)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request")
	})

	t.Run("Received bad request: bad encoded proof", func(t *testing.T) {
		op := newOperation(t, newConfig())
		handler := getHandler(t, op, verifyProofEndpoint, http.MethodPost)

		nonce := base64.URLEncoding.EncodeToString([]byte("nonce"))

		req := buildVerifyProofReq(t, base64.URLEncoding.EncodeToString([]byte("message")), "!proof", nonce)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request")
	})

	t.Run("Received bad request: bad encoded nonce", func(t *testing.T) {
		op := newOperation(t, newConfig())
		handler := getHandler(t, op, verifyProofEndpoint, http.MethodPost)

		proof := base64.URLEncoding.EncodeToString([]byte("proof"))

		req := buildVerifyProofReq(t, base64.URLEncoding.EncodeToString([]byte("message")), proof, "!nonce")

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request")
	})

	t.Run("Failed to resolve a keystore", func(t *testing.T) {
		svc := &mockkms.MockService{ResolveKeystoreErr: errors.New("resolve keystore error")}

		op := newOperation(t, newConfig(withKMSService(svc)))
		handler := getHandler(t, op, verifyProofEndpoint, http.MethodPost)

		proof := base64.URLEncoding.EncodeToString([]byte("proof"))
		nonce := base64.URLEncoding.EncodeToString([]byte("nonce"))

		req := buildVerifyProofReq(t, base64.URLEncoding.EncodeToString([]byte("message")), proof, nonce)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to resolve a keystore: resolve keystore error")
	})

	t.Run("Failed to get key handle", func(t *testing.T) {
		svc := mockKMSService()
		svc.ResolveKeystoreValue = &keystore.MockKeystore{GetKeyHandleErr: errors.New("get key handle error")}

		op := newOperation(t, newConfig(withKMSService(svc)))
		handler := getHandler(t, op, verifyProofEndpoint, http.MethodPost)

		proof := base64.URLEncoding.EncodeToString([]byte("proof"))
		nonce := base64.URLEncoding.EncodeToString([]byte("nonce"))

		req := buildVerifyProofReq(t, base64.URLEncoding.EncodeToString([]byte("message")), proof, nonce)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to verify proof: get key handle error")
	})

	t.Run("Failed to verify proof", func(t *testing.T) {
		svc := mockKMSService()
		svc.VerifyProofErr = errors.New("verify proof error")

		op := newOperation(t, newConfig(withKMSService(svc)))
		handler := getHandler(t, op, verifyProofEndpoint, http.MethodPost)

		proof := base64.URLEncoding.EncodeToString([]byte("proof"))
		nonce := base64.URLEncoding.EncodeToString([]byte("nonce"))

		req := buildVerifyProofReq(t, base64.URLEncoding.EncodeToString([]byte("message")), proof, nonce)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to verify proof: verify proof error")
	})
}

func buildSignMultiReq(t *testing.T, msg1, msg2 string) *http.Request {
	t.Helper()

	payload := fmt.Sprintf(signMultiReqFormat, msg1, msg2)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", bytes.NewBuffer([]byte(payload)))
	require.NoError(t, err)

	req = mux.SetURLVars(req, map[string]string{
		"keystoreID": testKeystoreID,
		"keyID":      testKeyID,
	})

	return req
}

func buildVerifyMultiReq(t *testing.T, sig, msg1, msg2 string) *http.Request {
	t.Helper()

	payload := fmt.Sprintf(verifyMultiReqFormat, sig, msg1, msg2)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", bytes.NewBuffer([]byte(payload)))
	require.NoError(t, err)

	req = mux.SetURLVars(req, map[string]string{
		"keystoreID": testKeystoreID,
		"keyID":      testKeyID,
	})

	return req
}

func buildDeriveProofReq(t *testing.T, msg1, msg2, sig, nonce string) *http.Request {
	t.Helper()

	payload := fmt.Sprintf(deriveProofReqFormat, msg1, msg2, sig, nonce)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", bytes.NewBuffer([]byte(payload)))
	require.NoError(t, err)

	req = mux.SetURLVars(req, map[string]string{
		"keystoreID": testKeystoreID,
		"keyID":      testKeyID,
	})

	return req
}

func buildVerifyProofReq(t *testing.T, msg, proof, nonce string) *http.Request {
	t.Helper()

	payload := fmt.Sprintf(verifyProofReqFormat, msg, proof, nonce)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", bytes.NewBuffer([]byte(payload)))
	require.NoError(t, err)

	req = mux.SetURLVars(req, map[string]string{
		"keystoreID": testKeystoreID,
		"keyID":      testKeyID,
	})

	return req
}
