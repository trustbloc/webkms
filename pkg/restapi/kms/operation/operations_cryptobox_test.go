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

	mockkms "github.com/trustbloc/hub-kms/pkg/internal/mock/kms"
)

const (
	easyEndpoint     = "/keystores/{keystoreID}/keys/{keyID}/easy"
	easyOpenEndpoint = "/keystores/{keystoreID}/easyopen"
	sealOpenEndpoint = "/keystores/{keystoreID}/sealopen"
)

func TestEasyHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		cb := &mockCryptoBox{EasyValue: []byte("cipher text")}
		op := newOperation(t, newConfig(withCryptoBox(cb)))
		handler := getHandler(t, op, easyEndpoint, http.MethodPost)

		payload := base64.URLEncoding.EncodeToString([]byte("payload"))
		nonce := base64.URLEncoding.EncodeToString([]byte("nonce"))
		theirPub := base64.URLEncoding.EncodeToString([]byte("their pub"))

		req := buildEasyReq(t, payload, nonce, theirPub)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusOK, rr.Code)
		require.Contains(t, rr.Body.String(), base64.URLEncoding.EncodeToString([]byte("cipher text")))
	})

	t.Run("Received bad request: EOF", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", bytes.NewBuffer([]byte("")))
		require.NoError(t, err)

		op := newOperation(t, newConfig())
		handler := getHandler(t, op, easyEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request: EOF")
	})

	t.Run("Received bad request: bad encoded payload", func(t *testing.T) {
		op := newOperation(t, newConfig())
		handler := getHandler(t, op, easyEndpoint, http.MethodPost)

		nonce := base64.URLEncoding.EncodeToString([]byte("nonce"))
		theirPub := base64.URLEncoding.EncodeToString([]byte("their pub"))

		req := buildEasyReq(t, "!payload", nonce, theirPub)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request")
	})

	t.Run("Received bad request: bad encoded nonce", func(t *testing.T) {
		op := newOperation(t, newConfig())
		handler := getHandler(t, op, easyEndpoint, http.MethodPost)

		payload := base64.URLEncoding.EncodeToString([]byte("payload"))
		theirPub := base64.URLEncoding.EncodeToString([]byte("their pub"))

		req := buildEasyReq(t, payload, "!nonce", theirPub)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request")
	})

	t.Run("Received bad request: bad encoded theirPub", func(t *testing.T) {
		op := newOperation(t, newConfig())
		handler := getHandler(t, op, easyEndpoint, http.MethodPost)

		payload := base64.URLEncoding.EncodeToString([]byte("payload"))
		nonce := base64.URLEncoding.EncodeToString([]byte("nonce"))

		req := buildEasyReq(t, payload, nonce, "!theirPub")

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request")
	})

	t.Run("Failed to resolve a keystore", func(t *testing.T) {
		svc := &mockkms.MockService{ResolveKeystoreErr: errors.New("resolve keystore error")}

		op := newOperation(t, newConfig(withKMSService(svc)))
		handler := getHandler(t, op, easyEndpoint, http.MethodPost)

		payload := base64.URLEncoding.EncodeToString([]byte("payload"))
		nonce := base64.URLEncoding.EncodeToString([]byte("nonce"))
		theirPub := base64.URLEncoding.EncodeToString([]byte("their pub"))

		req := buildEasyReq(t, payload, nonce, theirPub)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to resolve a keystore: resolve keystore error")
	})

	t.Run("Failed to create a CryptoBox instance", func(t *testing.T) {
		op := newOperation(t, newConfig(withCryptoBoxCreatorErr(errors.New("creator error"))))
		handler := getHandler(t, op, easyEndpoint, http.MethodPost)

		payload := base64.URLEncoding.EncodeToString([]byte("payload"))
		nonce := base64.URLEncoding.EncodeToString([]byte("nonce"))
		theirPub := base64.URLEncoding.EncodeToString([]byte("their pub"))

		req := buildEasyReq(t, payload, nonce, theirPub)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to easy a message: creator error")
	})

	t.Run("Failed to easy a message", func(t *testing.T) {
		cb := &mockCryptoBox{EasyErr: errors.New("easy error")}
		op := newOperation(t, newConfig(withCryptoBox(cb)))
		handler := getHandler(t, op, easyEndpoint, http.MethodPost)

		payload := base64.URLEncoding.EncodeToString([]byte("payload"))
		nonce := base64.URLEncoding.EncodeToString([]byte("nonce"))
		theirPub := base64.URLEncoding.EncodeToString([]byte("their pub"))

		req := buildEasyReq(t, payload, nonce, theirPub)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to easy a message: easy error")
	})
}

func TestEasyOpenHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		cb := &mockCryptoBox{EasyOpenValue: []byte("plain text")}
		op := newOperation(t, newConfig(withCryptoBox(cb)))
		handler := getHandler(t, op, easyOpenEndpoint, http.MethodPost)

		cipherText := base64.URLEncoding.EncodeToString([]byte("cipher text"))
		nonce := base64.URLEncoding.EncodeToString([]byte("nonce"))
		theirPub := base64.URLEncoding.EncodeToString([]byte("their pub"))
		myPub := base64.URLEncoding.EncodeToString([]byte("my pub"))

		req := buildEasyOpenReq(t, cipherText, nonce, theirPub, myPub)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusOK, rr.Code)
		require.Contains(t, rr.Body.String(), base64.URLEncoding.EncodeToString([]byte("plain text")))
	})

	t.Run("Received bad request: EOF", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", bytes.NewBuffer([]byte("")))
		require.NoError(t, err)

		op := newOperation(t, newConfig())
		handler := getHandler(t, op, easyOpenEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request: EOF")
	})

	t.Run("Received bad request: bad encoded cipherText", func(t *testing.T) {
		op := newOperation(t, newConfig())
		handler := getHandler(t, op, easyOpenEndpoint, http.MethodPost)

		nonce := base64.URLEncoding.EncodeToString([]byte("nonce"))
		theirPub := base64.URLEncoding.EncodeToString([]byte("their pub"))
		myPub := base64.URLEncoding.EncodeToString([]byte("my pub"))

		req := buildEasyOpenReq(t, "!cipherText", nonce, theirPub, myPub)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request")
	})

	t.Run("Received bad request: bad encoded nonce", func(t *testing.T) {
		op := newOperation(t, newConfig())
		handler := getHandler(t, op, easyOpenEndpoint, http.MethodPost)

		cipherText := base64.URLEncoding.EncodeToString([]byte("cipher text"))
		theirPub := base64.URLEncoding.EncodeToString([]byte("their pub"))
		myPub := base64.URLEncoding.EncodeToString([]byte("my pub"))

		req := buildEasyOpenReq(t, cipherText, "!nonce", theirPub, myPub)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request")
	})

	t.Run("Received bad request: bad encoded theirPub", func(t *testing.T) {
		op := newOperation(t, newConfig())
		handler := getHandler(t, op, easyOpenEndpoint, http.MethodPost)

		cipherText := base64.URLEncoding.EncodeToString([]byte("cipher text"))
		nonce := base64.URLEncoding.EncodeToString([]byte("nonce"))
		myPub := base64.URLEncoding.EncodeToString([]byte("my pub"))

		req := buildEasyOpenReq(t, cipherText, nonce, "!theirPub", myPub)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request")
	})

	t.Run("Received bad request: bad encoded myPub", func(t *testing.T) {
		op := newOperation(t, newConfig())
		handler := getHandler(t, op, easyOpenEndpoint, http.MethodPost)

		cipherText := base64.URLEncoding.EncodeToString([]byte("cipher text"))
		nonce := base64.URLEncoding.EncodeToString([]byte("nonce"))
		theirPub := base64.URLEncoding.EncodeToString([]byte("their pub"))

		req := buildEasyOpenReq(t, cipherText, nonce, theirPub, "!myPub")

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request")
	})

	t.Run("Failed to resolve a keystore", func(t *testing.T) {
		svc := &mockkms.MockService{ResolveKeystoreErr: errors.New("resolve keystore error")}

		op := newOperation(t, newConfig(withKMSService(svc)))
		handler := getHandler(t, op, easyOpenEndpoint, http.MethodPost)

		cipherText := base64.URLEncoding.EncodeToString([]byte("cipher text"))
		nonce := base64.URLEncoding.EncodeToString([]byte("nonce"))
		theirPub := base64.URLEncoding.EncodeToString([]byte("their pub"))
		myPub := base64.URLEncoding.EncodeToString([]byte("my pub"))

		req := buildEasyOpenReq(t, cipherText, nonce, theirPub, myPub)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to resolve a keystore: resolve keystore error")
	})

	t.Run("Failed to create a CryptoBox instance", func(t *testing.T) {
		op := newOperation(t, newConfig(withCryptoBoxCreatorErr(errors.New("creator error"))))
		handler := getHandler(t, op, easyOpenEndpoint, http.MethodPost)

		cipherText := base64.URLEncoding.EncodeToString([]byte("cipher text"))
		nonce := base64.URLEncoding.EncodeToString([]byte("nonce"))
		theirPub := base64.URLEncoding.EncodeToString([]byte("their pub"))
		myPub := base64.URLEncoding.EncodeToString([]byte("my pub"))

		req := buildEasyOpenReq(t, cipherText, nonce, theirPub, myPub)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to easyOpen a message: creator error")
	})

	t.Run("Failed to easy open a message", func(t *testing.T) {
		cb := &mockCryptoBox{EasyOpenErr: errors.New("easy open error")}
		op := newOperation(t, newConfig(withCryptoBox(cb)))
		handler := getHandler(t, op, easyOpenEndpoint, http.MethodPost)

		cipherText := base64.URLEncoding.EncodeToString([]byte("cipher text"))
		nonce := base64.URLEncoding.EncodeToString([]byte("nonce"))
		theirPub := base64.URLEncoding.EncodeToString([]byte("their pub"))
		myPub := base64.URLEncoding.EncodeToString([]byte("my pub"))

		req := buildEasyOpenReq(t, cipherText, nonce, theirPub, myPub)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to easyOpen a message: easy open error")
	})
}

func TestSealOpenHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		cb := &mockCryptoBox{SealOpenValue: []byte("plain text")}
		op := newOperation(t, newConfig(withCryptoBox(cb)))
		handler := getHandler(t, op, sealOpenEndpoint, http.MethodPost)

		cipherText := base64.URLEncoding.EncodeToString([]byte("cipher text"))
		myPub := base64.URLEncoding.EncodeToString([]byte("my pub"))

		req := buildSealOpenReq(t, cipherText, myPub)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusOK, rr.Code)
		require.Contains(t, rr.Body.String(), base64.URLEncoding.EncodeToString([]byte("plain text")))
	})

	t.Run("Received bad request: EOF", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", bytes.NewBuffer([]byte("")))
		require.NoError(t, err)

		op := newOperation(t, newConfig())
		handler := getHandler(t, op, sealOpenEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request: EOF")
	})

	t.Run("Received bad request: bad encoded cipherText", func(t *testing.T) {
		op := newOperation(t, newConfig())
		handler := getHandler(t, op, sealOpenEndpoint, http.MethodPost)

		myPub := base64.URLEncoding.EncodeToString([]byte("my pub"))

		req := buildSealOpenReq(t, "!cipherText", myPub)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request")
	})

	t.Run("Received bad request: bad encoded myPub", func(t *testing.T) {
		op := newOperation(t, newConfig())
		handler := getHandler(t, op, sealOpenEndpoint, http.MethodPost)

		cipherText := base64.URLEncoding.EncodeToString([]byte("cipher text"))

		req := buildSealOpenReq(t, cipherText, "!myPub")

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request")
	})

	t.Run("Failed to resolve a keystore", func(t *testing.T) {
		svc := &mockkms.MockService{ResolveKeystoreErr: errors.New("resolve keystore error")}

		op := newOperation(t, newConfig(withKMSService(svc)))
		handler := getHandler(t, op, sealOpenEndpoint, http.MethodPost)

		cipherText := base64.URLEncoding.EncodeToString([]byte("cipher text"))
		myPub := base64.URLEncoding.EncodeToString([]byte("my pub"))

		req := buildSealOpenReq(t, cipherText, myPub)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to resolve a keystore: resolve keystore error")
	})

	t.Run("Failed to create a CryptoBox instance", func(t *testing.T) {
		op := newOperation(t, newConfig(withCryptoBoxCreatorErr(errors.New("creator error"))))
		handler := getHandler(t, op, sealOpenEndpoint, http.MethodPost)

		cipherText := base64.URLEncoding.EncodeToString([]byte("cipher text"))
		myPub := base64.URLEncoding.EncodeToString([]byte("my pub"))

		req := buildSealOpenReq(t, cipherText, myPub)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to sealOpen a payload: creator error")
	})

	t.Run("Failed to seal open a payload", func(t *testing.T) {
		cb := &mockCryptoBox{SealOpenErr: errors.New("seal open error")}
		op := newOperation(t, newConfig(withCryptoBox(cb)))
		handler := getHandler(t, op, sealOpenEndpoint, http.MethodPost)

		cipherText := base64.URLEncoding.EncodeToString([]byte("cipher text"))
		myPub := base64.URLEncoding.EncodeToString([]byte("my pub"))

		req := buildSealOpenReq(t, cipherText, myPub)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to sealOpen a payload: seal open error")
	})
}

func buildEasyReq(t *testing.T, payload, nonce, theirPub string) *http.Request {
	t.Helper()

	p := fmt.Sprintf(easyReqFormat, payload, nonce, theirPub)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", bytes.NewBuffer([]byte(p)))
	require.NoError(t, err)

	req = mux.SetURLVars(req, map[string]string{
		"keystoreID": testKeystoreID,
		"keyID":      testKeyID,
	})

	return req
}

func buildEasyOpenReq(t *testing.T, cipherText, nonce, theirPub, myPub string) *http.Request {
	t.Helper()

	p := fmt.Sprintf(easyOpenReqFormat, cipherText, nonce, theirPub, myPub)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", bytes.NewBuffer([]byte(p)))
	require.NoError(t, err)

	req = mux.SetURLVars(req, map[string]string{
		"keystoreID": testKeystoreID,
	})

	return req
}

func buildSealOpenReq(t *testing.T, cipherText, myPub string) *http.Request {
	t.Helper()

	p := fmt.Sprintf(sealOpenReqFormat, cipherText, myPub)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", bytes.NewBuffer([]byte(p)))
	require.NoError(t, err)

	req = mux.SetURLVars(req, map[string]string{
		"keystoreID": testKeystoreID,
	})

	return req
}
