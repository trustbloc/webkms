/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	arieskms "github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/log/mocklogger"
	"github.com/trustbloc/edge-core/pkg/zcapld"
	"go.opentelemetry.io/otel/oteltest"
	"go.opentelemetry.io/otel/trace"

	"github.com/trustbloc/hub-kms/pkg/internal/mock/keystore"
	mockkms "github.com/trustbloc/hub-kms/pkg/internal/mock/kms"
	"github.com/trustbloc/hub-kms/pkg/kms"
	"github.com/trustbloc/hub-kms/pkg/restapi/kms/operation"
)

const (
	testKeystoreID = "bsi5ct08vcqmquc0fn5g"
	testKeyID      = "Fm4r2iwjYnswLRZKl38W"
	testController = "did:example:123456789"
)

const (
	keystoresEndpoint  = "/keystores"
	keysEndpoint       = "/keystores/{keystoreID}/keys"
	capabilityEndpoint = "/keystores/{keystoreID}/capability"
	exportEndpoint     = "/keystores/{keystoreID}/keys/{keyID}/export"
	signEndpoint       = "/keystores/{keystoreID}/keys/{keyID}/sign"
	verifyEndpoint     = "/keystores/{keystoreID}/keys/{keyID}/verify"
	encryptEndpoint    = "/keystores/{keystoreID}/keys/{keyID}/encrypt"
	decryptEndpoint    = "/keystores/{keystoreID}/keys/{keyID}/decrypt"
	computeMACEndpoint = "/keystores/{keystoreID}/keys/{keyID}/computemac"
	verifyMACEndpoint  = "/keystores/{keystoreID}/keys/{keyID}/verifymac"
	wrapEndpoint       = "/keystores/{keystoreID}/wrap"
	unwrapEndpoint     = "/keystores/{keystoreID}/keys/{keyID}/unwrap"
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

	publicKeyFormat = `{
	  "kid": "%s",
	  "x": "%s",
	  "y": "%s",
	  "curve": "%s",
	  "type": "%s"
	}`

	wrapReqFormat = `{
	  "cek": "%s",
	  "apu": "%s",
	  "apv": "%s",
	  "recPubKey": %s,
	  "senderKID": "%s"
	}`

	wrappedKeyFormat = `{
	  "kid": "%s",
	  "encryptedCEK": "%s",
	  "epk": %s,
	  "alg": "%s",
	  "apu": "%s",
	  "apv": "%s"
	}`

	unwrapReqFormat = `{
	  "wrappedKey": %s,
	  "senderKID": "%s"
	}`

	easyReqFormat = `{
	  "payload": "%s",
	  "nonce": "%s",
	  "theirPub": "%s"
	}`

	easyOpenReqFormat = `{
	  "cipherText": "%s",
	  "nonce": "%s",
	  "theirPub": "%s",
	  "myPub": "%s"
	}`

	sealOpenReqFormat = `{
	  "cipherText": "%s",
	  "myPub": "%s"
	}`
)

func TestNew(t *testing.T) {
	op := newOperation(t, newConfig())
	require.NotNil(t, op)
}

func TestCreateKeystoreHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		op := newOperation(t, newConfig())
		handler := getHandler(t, op, keystoresEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildCreateKeystoreReq(t))

		require.Equal(t, http.StatusCreated, rr.Code)
		require.NotEmpty(t, rr.Header().Get("Location"))
	})

	t.Run("Error from create did key", func(t *testing.T) {
		svc := &mockAuthService{createDIDKeyFunc: func(context.Context) (string, error) {
			return "", fmt.Errorf("failed to create did key")
		}}

		op := newOperation(t, newConfig(withAuthService(svc)))
		handler := getHandler(t, op, keystoresEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildCreateKeystoreReq(t))

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to create did key")
	})

	t.Run("Received bad request", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", bytes.NewBuffer([]byte("")))
		require.NoError(t, err)

		op := newOperation(t, newConfig())
		handler := getHandler(t, op, keystoresEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request: EOF")
	})

	t.Run("Failed to create a keystore", func(t *testing.T) {
		svc := &mockkms.MockService{CreateKeystoreErr: errors.New("create keystore error")}

		op := newOperation(t, newConfig(withKMSService(svc)))
		handler := getHandler(t, op, keystoresEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildCreateKeystoreReq(t))

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to create a keystore: create keystore error")
	})

	t.Run("internal server error if cannot create zcap", func(t *testing.T) {
		svc := &mockAuthService{newCapabilityErr: errors.New("test")}

		op := newOperation(t, newConfig(withAuthService(svc)))
		handler := getHandler(t, op, keystoresEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildCreateKeystoreReq(t))

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to create zcap")
	})
}

func TestUpdateCapabilityHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		op := newOperation(t, newConfig())
		handler := getHandler(t, op, capabilityEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildUpdateCapabilityReq(t, []byte("{}")))

		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("test error from get keystore data", func(t *testing.T) {
		svc := mockKMSService()
		svc.GetKeystoreDataErr = errors.New("get keystore data error")

		op := newOperation(t, newConfig(withKMSService(svc)))
		handler := getHandler(t, op, capabilityEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildUpdateCapabilityReq(t, []byte("{}")))

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "get keystore data error")
	})

	t.Run("test error from save keystore data", func(t *testing.T) {
		svc := mockKMSService()
		svc.SaveKeystoreDataErr = errors.New("save keystore data error")

		op := newOperation(t, newConfig(withKMSService(svc)))
		handler := getHandler(t, op, capabilityEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildUpdateCapabilityReq(t, []byte("{}")))

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "save keystore data error")
	})

	t.Run("test empty capability", func(t *testing.T) {
		op := newOperation(t, newConfig())
		handler := getHandler(t, op, capabilityEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildUpdateCapabilityReq(t, nil))

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "edvCapability is empty")
	})
}

func TestCreateKeyHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		op := newOperation(t, newConfig())
		handler := getHandler(t, op, keysEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildCreateKeyReq(t))

		require.Equal(t, http.StatusCreated, rr.Code)
		require.NotEmpty(t, rr.Header().Get("Location"))
	})

	t.Run("Received bad request", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", bytes.NewBuffer([]byte("")))
		require.NoError(t, err)

		op := newOperation(t, newConfig())
		handler := getHandler(t, op, keysEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request: EOF")
	})

	t.Run("Failed to resolve a keystore", func(t *testing.T) {
		svc := &mockkms.MockService{ResolveKeystoreErr: errors.New("resolve keystore error")}

		op := newOperation(t, newConfig(withKMSService(svc)))
		handler := getHandler(t, op, keysEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildCreateKeyReq(t))

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to resolve a keystore: resolve keystore error")
	})

	t.Run("Failed to create a key", func(t *testing.T) {
		svc := &mockkms.MockService{}
		svc.ResolveKeystoreValue = &keystore.MockKeystore{CreateKeyErr: errors.New("create key error")}

		op := newOperation(t, newConfig(withKMSService(svc)))
		handler := getHandler(t, op, keysEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildCreateKeyReq(t))

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to create a key: create key error")
	})
}

func TestExportKeyHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		svc := mockKMSService()
		svc.ResolveKeystoreValue = &keystore.MockKeystore{ExportKeyValue: []byte("public key bytes")}

		op := newOperation(t, newConfig(withKMSService(svc)))
		handler := getHandler(t, op, exportEndpoint, http.MethodGet)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildExportKeyReq(t))

		require.Equal(t, http.StatusOK, rr.Code)
		require.Contains(t, rr.Body.String(), base64.URLEncoding.EncodeToString([]byte("public key bytes")))
	})

	t.Run("Failed to resolve a keystore", func(t *testing.T) {
		svc := &mockkms.MockService{ResolveKeystoreErr: errors.New("resolve keystore error")}

		op := newOperation(t, newConfig(withKMSService(svc)))
		handler := getHandler(t, op, exportEndpoint, http.MethodGet)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildExportKeyReq(t))

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to resolve a keystore: resolve keystore error")
	})

	t.Run("Failed to export a public key", func(t *testing.T) {
		svc := mockKMSService()
		svc.ResolveKeystoreValue = &keystore.MockKeystore{ExportKeyErr: errors.New("export key error")}

		op := newOperation(t, newConfig(withKMSService(svc)))
		handler := getHandler(t, op, exportEndpoint, http.MethodGet)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildExportKeyReq(t))

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to export a public key: export key error")
	})
}

func TestSignHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		svc := mockKMSService()
		svc.SignValue = []byte("signature")

		op := newOperation(t, newConfig(withKMSService(svc)))
		handler := getHandler(t, op, signEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildSignReq(t, base64.URLEncoding.EncodeToString([]byte("test message"))))

		require.Equal(t, http.StatusOK, rr.Code)
		require.Contains(t, rr.Body.String(), base64.URLEncoding.EncodeToString([]byte("signature")))
	})

	t.Run("Received bad request: EOF", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", bytes.NewBuffer([]byte("")))
		require.NoError(t, err)

		op := newOperation(t, newConfig())
		handler := getHandler(t, op, signEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request: EOF")
	})

	t.Run("Received bad request: bad encoded message", func(t *testing.T) {
		op := newOperation(t, newConfig())
		handler := getHandler(t, op, signEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildSignReq(t, "!message"))

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request")
	})

	t.Run("Failed to resolve a keystore", func(t *testing.T) {
		svc := &mockkms.MockService{ResolveKeystoreErr: errors.New("resolve keystore error")}

		op := newOperation(t, newConfig(withKMSService(svc)))
		handler := getHandler(t, op, signEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildSignReq(t, base64.URLEncoding.EncodeToString([]byte("test message"))))

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to resolve a keystore: resolve keystore error")
	})

	t.Run("Failed to get key handle", func(t *testing.T) {
		svc := mockKMSService()
		svc.ResolveKeystoreValue = &keystore.MockKeystore{GetKeyHandleErr: errors.New("get key handle error")}

		op := newOperation(t, newConfig(withKMSService(svc)))
		handler := getHandler(t, op, signEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildSignReq(t, base64.URLEncoding.EncodeToString([]byte("test message"))))

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to sign a message: get key handle error")
	})

	t.Run("Failed to sign a message", func(t *testing.T) {
		svc := mockKMSService()
		svc.SignErr = errors.New("sign error")

		op := newOperation(t, newConfig(withKMSService(svc)))
		handler := getHandler(t, op, signEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildSignReq(t, base64.URLEncoding.EncodeToString([]byte("test message"))))

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to sign a message: sign error")
	})
}

func TestVerifyHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		op := newOperation(t, newConfig())
		handler := getHandler(t, op, verifyEndpoint, http.MethodPost)

		sig := base64.URLEncoding.EncodeToString([]byte("test signature"))
		msg := base64.URLEncoding.EncodeToString([]byte("test message"))
		req := buildVerifyReq(t, sig, msg)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Received bad request: EOF", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", bytes.NewBuffer([]byte("")))
		require.NoError(t, err)

		op := newOperation(t, newConfig())
		handler := getHandler(t, op, verifyEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request: EOF")
	})

	t.Run("Received bad request: bad encoded signature", func(t *testing.T) {
		op := newOperation(t, newConfig())
		handler := getHandler(t, op, verifyEndpoint, http.MethodPost)

		msg := base64.URLEncoding.EncodeToString([]byte("test message"))
		req := buildVerifyReq(t, "!signature", msg)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request")
	})

	t.Run("Received bad request: bad encoded message", func(t *testing.T) {
		op := newOperation(t, newConfig())
		handler := getHandler(t, op, verifyEndpoint, http.MethodPost)

		sig := base64.URLEncoding.EncodeToString([]byte("test signature"))
		req := buildVerifyReq(t, sig, "!message")

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request")
	})

	t.Run("Failed to resolve a keystore", func(t *testing.T) {
		svc := &mockkms.MockService{ResolveKeystoreErr: errors.New("resolve keystore error")}

		op := newOperation(t, newConfig(withKMSService(svc)))
		handler := getHandler(t, op, verifyEndpoint, http.MethodPost)

		sig := base64.URLEncoding.EncodeToString([]byte("test signature"))
		msg := base64.URLEncoding.EncodeToString([]byte("test message"))
		req := buildVerifyReq(t, sig, msg)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to resolve a keystore: resolve keystore error")
	})

	t.Run("Failed to get key handle", func(t *testing.T) {
		svc := mockKMSService()
		svc.ResolveKeystoreValue = &keystore.MockKeystore{GetKeyHandleErr: errors.New("get key handle error")}

		op := newOperation(t, newConfig(withKMSService(svc)))
		handler := getHandler(t, op, verifyEndpoint, http.MethodPost)

		sig := base64.URLEncoding.EncodeToString([]byte("test signature"))
		msg := base64.URLEncoding.EncodeToString([]byte("test message"))
		req := buildVerifyReq(t, sig, msg)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to verify a message: get key handle error")
	})

	t.Run("Failed to verify a message: verify error", func(t *testing.T) {
		svc := mockKMSService()
		svc.VerifyErr = errors.New("verify error")

		op := newOperation(t, newConfig(withKMSService(svc)))
		handler := getHandler(t, op, verifyEndpoint, http.MethodPost)

		sig := base64.URLEncoding.EncodeToString([]byte("test signature"))
		msg := base64.URLEncoding.EncodeToString([]byte("test message"))
		req := buildVerifyReq(t, sig, msg)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to verify a message: verify error")
	})
}

func TestEncryptHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		svc := mockKMSService()
		svc.EncryptValue = []byte("cipher text")

		op := newOperation(t, newConfig(withKMSService(svc)))
		handler := getHandler(t, op, encryptEndpoint, http.MethodPost)

		msg := base64.URLEncoding.EncodeToString([]byte("test message"))
		aad := base64.URLEncoding.EncodeToString([]byte("additional data"))
		req := buildEncryptReq(t, msg, aad)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusOK, rr.Code)
		require.Contains(t, rr.Body.String(), base64.URLEncoding.EncodeToString([]byte("cipher text")))
	})

	t.Run("Received bad request: EOF", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", bytes.NewBuffer([]byte("")))
		require.NoError(t, err)

		op := newOperation(t, newConfig())
		handler := getHandler(t, op, encryptEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request: EOF")
	})

	t.Run("Received bad request: bad encoded message", func(t *testing.T) {
		op := newOperation(t, newConfig())
		handler := getHandler(t, op, encryptEndpoint, http.MethodPost)

		aad := base64.URLEncoding.EncodeToString([]byte("additional data"))
		req := buildEncryptReq(t, "!message", aad)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request")
	})

	t.Run("Received bad request: bad encoded aad", func(t *testing.T) {
		op := newOperation(t, newConfig())
		handler := getHandler(t, op, encryptEndpoint, http.MethodPost)

		msg := base64.URLEncoding.EncodeToString([]byte("test message"))
		req := buildEncryptReq(t, msg, "!aad")

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request")
	})

	t.Run("Failed to resolve a keystore", func(t *testing.T) {
		svc := &mockkms.MockService{ResolveKeystoreErr: errors.New("resolve keystore error")}

		op := newOperation(t, newConfig(withKMSService(svc)))
		handler := getHandler(t, op, encryptEndpoint, http.MethodPost)

		msg := base64.URLEncoding.EncodeToString([]byte("test message"))
		aad := base64.URLEncoding.EncodeToString([]byte("additional data"))
		req := buildEncryptReq(t, msg, aad)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to resolve a keystore: resolve keystore error")
	})

	t.Run("Failed to get key handle", func(t *testing.T) {
		svc := mockKMSService()
		svc.ResolveKeystoreValue = &keystore.MockKeystore{GetKeyHandleErr: errors.New("get key handle error")}

		op := newOperation(t, newConfig(withKMSService(svc)))
		handler := getHandler(t, op, encryptEndpoint, http.MethodPost)

		msg := base64.URLEncoding.EncodeToString([]byte("test message"))
		aad := base64.URLEncoding.EncodeToString([]byte("additional data"))
		req := buildEncryptReq(t, msg, aad)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to encrypt a message: get key handle error")
	})

	t.Run("Failed to encrypt a message", func(t *testing.T) {
		svc := mockKMSService()
		svc.EncryptErr = errors.New("encrypt error")

		op := newOperation(t, newConfig(withKMSService(svc)))
		handler := getHandler(t, op, encryptEndpoint, http.MethodPost)

		msg := base64.URLEncoding.EncodeToString([]byte("test message"))
		aad := base64.URLEncoding.EncodeToString([]byte("additional data"))
		req := buildEncryptReq(t, msg, aad)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to encrypt a message: encrypt error")
	})
}

func TestDecryptHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		svc := mockKMSService()
		svc.DecryptValue = []byte("plain text")

		op := newOperation(t, newConfig(withKMSService(svc)))
		handler := getHandler(t, op, decryptEndpoint, http.MethodPost)

		cipherText := base64.URLEncoding.EncodeToString([]byte("test cipher text"))
		aad := base64.URLEncoding.EncodeToString([]byte("additional data"))
		nonce := base64.URLEncoding.EncodeToString([]byte("test nonce"))
		req := buildDecryptReq(t, cipherText, aad, nonce)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusOK, rr.Code)
		require.Contains(t, rr.Body.String(), base64.URLEncoding.EncodeToString([]byte("plain text")))
	})

	t.Run("Received bad request: EOF", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", bytes.NewBuffer([]byte("")))
		require.NoError(t, err)

		op := newOperation(t, newConfig())
		handler := getHandler(t, op, decryptEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request: EOF")
	})

	t.Run("Received bad request: bad encoded cipher text", func(t *testing.T) {
		op := newOperation(t, newConfig())
		handler := getHandler(t, op, decryptEndpoint, http.MethodPost)

		aad := base64.URLEncoding.EncodeToString([]byte("additional data"))
		nonce := base64.URLEncoding.EncodeToString([]byte("test nonce"))
		req := buildDecryptReq(t, "!cipher", aad, nonce)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request")
	})

	t.Run("Received bad request: bad encoded aad", func(t *testing.T) {
		op := newOperation(t, newConfig())
		handler := getHandler(t, op, decryptEndpoint, http.MethodPost)

		cipherText := base64.URLEncoding.EncodeToString([]byte("test cipher text"))
		nonce := base64.URLEncoding.EncodeToString([]byte("test nonce"))
		req := buildDecryptReq(t, cipherText, "!aad", nonce)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request")
	})

	t.Run("Received bad request: bad encoded nonce", func(t *testing.T) {
		op := newOperation(t, newConfig())
		handler := getHandler(t, op, decryptEndpoint, http.MethodPost)

		cipherText := base64.URLEncoding.EncodeToString([]byte("test cipher text"))
		aad := base64.URLEncoding.EncodeToString([]byte("additional data"))
		req := buildDecryptReq(t, cipherText, aad, "!nonce")

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request")
	})

	t.Run("Failed to resolve a keystore", func(t *testing.T) {
		svc := &mockkms.MockService{ResolveKeystoreErr: errors.New("resolve keystore error")}

		op := newOperation(t, newConfig(withKMSService(svc)))
		handler := getHandler(t, op, decryptEndpoint, http.MethodPost)

		cipherText := base64.URLEncoding.EncodeToString([]byte("test cipher text"))
		aad := base64.URLEncoding.EncodeToString([]byte("additional data"))
		nonce := base64.URLEncoding.EncodeToString([]byte("test nonce"))
		req := buildDecryptReq(t, cipherText, aad, nonce)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to resolve a keystore: resolve keystore error")
	})

	t.Run("Failed to get key handle", func(t *testing.T) {
		svc := mockKMSService()
		svc.ResolveKeystoreValue = &keystore.MockKeystore{GetKeyHandleErr: errors.New("get key handle error")}

		op := newOperation(t, newConfig(withKMSService(svc)))
		handler := getHandler(t, op, decryptEndpoint, http.MethodPost)

		cipherText := base64.URLEncoding.EncodeToString([]byte("test cipher text"))
		aad := base64.URLEncoding.EncodeToString([]byte("additional data"))
		nonce := base64.URLEncoding.EncodeToString([]byte("test nonce"))
		req := buildDecryptReq(t, cipherText, aad, nonce)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to decrypt a message: get key handle error")
	})

	t.Run("Failed to decrypt a message", func(t *testing.T) {
		svc := mockKMSService()
		svc.DecryptErr = errors.New("decrypt error")

		op := newOperation(t, newConfig(withKMSService(svc)))
		handler := getHandler(t, op, decryptEndpoint, http.MethodPost)

		cipherText := base64.URLEncoding.EncodeToString([]byte("test cipher text"))
		aad := base64.URLEncoding.EncodeToString([]byte("additional data"))
		nonce := base64.URLEncoding.EncodeToString([]byte("test nonce"))
		req := buildDecryptReq(t, cipherText, aad, nonce)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to decrypt a message: decrypt error")
	})
}

func TestComputeMACHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		svc := mockKMSService()
		svc.ComputeMACValue = []byte("mac")

		op := newOperation(t, newConfig(withKMSService(svc)))
		handler := getHandler(t, op, computeMACEndpoint, http.MethodPost)

		data := base64.URLEncoding.EncodeToString([]byte("test data"))
		req := buildComputeMACReq(t, data)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusOK, rr.Code)
		require.Contains(t, rr.Body.String(), base64.URLEncoding.EncodeToString([]byte("mac")))
	})

	t.Run("Received bad request: EOF", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", bytes.NewBuffer([]byte("")))
		require.NoError(t, err)

		op := newOperation(t, newConfig())
		handler := getHandler(t, op, computeMACEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request: EOF")
	})

	t.Run("Received bad request: bad encoded data", func(t *testing.T) {
		op := newOperation(t, newConfig())
		handler := getHandler(t, op, computeMACEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildComputeMACReq(t, "!data"))

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request")
	})

	t.Run("Failed to resolve a keystore", func(t *testing.T) {
		svc := &mockkms.MockService{ResolveKeystoreErr: errors.New("resolve keystore error")}

		op := newOperation(t, newConfig(withKMSService(svc)))
		handler := getHandler(t, op, computeMACEndpoint, http.MethodPost)

		data := base64.URLEncoding.EncodeToString([]byte("test data"))
		req := buildComputeMACReq(t, data)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to resolve a keystore: resolve keystore error")
	})

	t.Run("Failed to get key handle", func(t *testing.T) {
		svc := mockKMSService()
		svc.ResolveKeystoreValue = &keystore.MockKeystore{GetKeyHandleErr: errors.New("get key handle error")}

		op := newOperation(t, newConfig(withKMSService(svc)))
		handler := getHandler(t, op, computeMACEndpoint, http.MethodPost)

		data := base64.URLEncoding.EncodeToString([]byte("test data"))
		req := buildComputeMACReq(t, data)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to compute MAC: get key handle error")
	})

	t.Run("Failed to compute MAC", func(t *testing.T) {
		svc := mockKMSService()
		svc.ComputeMACErr = errors.New("compute mac error")

		op := newOperation(t, newConfig(withKMSService(svc)))
		handler := getHandler(t, op, computeMACEndpoint, http.MethodPost)

		data := base64.URLEncoding.EncodeToString([]byte("test data"))
		req := buildComputeMACReq(t, data)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to compute MAC: compute mac error")
	})
}

func TestVerifyMACHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		svc := mockKMSService()
		svc.ComputeMACValue = []byte("mac")

		op := newOperation(t, newConfig(withKMSService(svc)))
		handler := getHandler(t, op, verifyMACEndpoint, http.MethodPost)

		mac := base64.URLEncoding.EncodeToString([]byte("mac"))
		data := base64.URLEncoding.EncodeToString([]byte("test data"))
		req := buildVerifyMACReq(t, mac, data)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Received bad request: EOF", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", bytes.NewBuffer([]byte("")))
		require.NoError(t, err)

		op := newOperation(t, newConfig())
		handler := getHandler(t, op, verifyMACEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request: EOF")
	})

	t.Run("Received bad request: bad encoded mac", func(t *testing.T) {
		op := newOperation(t, newConfig())
		handler := getHandler(t, op, verifyMACEndpoint, http.MethodPost)

		data := base64.URLEncoding.EncodeToString([]byte("test data"))
		req := buildVerifyMACReq(t, "!mac", data)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request")
	})

	t.Run("Received bad request: bad encoded data", func(t *testing.T) {
		op := newOperation(t, newConfig())
		handler := getHandler(t, op, verifyMACEndpoint, http.MethodPost)

		mac := base64.URLEncoding.EncodeToString([]byte("mac"))
		req := buildVerifyMACReq(t, mac, "!data")

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request")
	})

	t.Run("Failed to resolve a keystore", func(t *testing.T) {
		svc := &mockkms.MockService{ResolveKeystoreErr: errors.New("resolve keystore error")}

		op := newOperation(t, newConfig(withKMSService(svc)))
		handler := getHandler(t, op, verifyMACEndpoint, http.MethodPost)

		mac := base64.URLEncoding.EncodeToString([]byte("mac"))
		data := base64.URLEncoding.EncodeToString([]byte("test data"))
		req := buildVerifyMACReq(t, mac, data)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to resolve a keystore: resolve keystore error")
	})

	t.Run("Failed to get key handle", func(t *testing.T) {
		svc := mockKMSService()
		svc.ResolveKeystoreValue = &keystore.MockKeystore{GetKeyHandleErr: errors.New("get key handle error")}

		op := newOperation(t, newConfig(withKMSService(svc)))
		handler := getHandler(t, op, verifyMACEndpoint, http.MethodPost)

		mac := base64.URLEncoding.EncodeToString([]byte("mac"))
		data := base64.URLEncoding.EncodeToString([]byte("test data"))
		req := buildVerifyMACReq(t, mac, data)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to verify MAC: get key handle error")
	})

	t.Run("Failed to verify MAC", func(t *testing.T) {
		svc := mockKMSService()
		svc.VerifyMACErr = errors.New("verify mac error")

		op := newOperation(t, newConfig(withKMSService(svc)))
		handler := getHandler(t, op, verifyMACEndpoint, http.MethodPost)

		mac := base64.URLEncoding.EncodeToString([]byte("mac"))
		data := base64.URLEncoding.EncodeToString([]byte("test data"))
		req := buildVerifyMACReq(t, mac, data)

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
	logger := &mocklogger.MockLogger{}

	op := newOperation(t, newConfig(withLogger(logger)))
	handler := getHandler(t, op, signEndpoint, http.MethodPost)
	req := buildSignReq(t, base64.URLEncoding.EncodeToString([]byte("test message")))

	rr := failingResponseWriter{httptest.NewRecorder()}
	handler.Handle().ServeHTTP(rr, req)

	require.Empty(t, rr.Body.String())
	require.Contains(t, logger.ErrorLogContents, "Unable to send a response")
}

func TestFailToWriteErrorResponse(t *testing.T) {
	svc := &mockkms.MockService{ResolveKeystoreErr: errors.New("resolve keystore error")}
	logger := &mocklogger.MockLogger{}

	op := newOperation(t, newConfig(withKMSService(svc), withLogger(logger)))
	handler := getHandler(t, op, keysEndpoint, http.MethodPost)
	req := buildCreateKeyReq(t)

	rr := failingResponseWriter{httptest.NewRecorder()}
	handler.Handle().ServeHTTP(rr, req)

	require.Empty(t, rr.Body.String())
	require.Contains(t, logger.ErrorLogContents, "Unable to send an error message")
}

func newOperation(t *testing.T, c *operation.Config) *operation.Operation {
	t.Helper()

	op, err := operation.New(c)
	require.NoError(t, err)

	return op
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

func buildCreateKeystoreReq(t *testing.T) *http.Request {
	t.Helper()

	payload := fmt.Sprintf(createKeystoreReqFormat, testController)
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

func buildUpdateCapabilityReq(t *testing.T, capability []byte) *http.Request {
	t.Helper()

	b, err := json.Marshal(operation.UpdateCapabilityReq{EDVCapability: capability})
	require.NoError(t, err)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", bytes.NewBuffer(b))
	require.NoError(t, err)

	req = mux.SetURLVars(req, map[string]string{
		"keystoreID": testKeystoreID,
	})

	return req
}

func buildExportKeyReq(t *testing.T) *http.Request {
	t.Helper()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "", nil)
	require.NoError(t, err)

	req = mux.SetURLVars(req, map[string]string{
		"keystoreID": testKeystoreID,
		"keyID":      testKeyID,
	})

	return req
}

func buildSignReq(t *testing.T, message string) *http.Request {
	t.Helper()

	payload := fmt.Sprintf(signReqFormat, message)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", bytes.NewBuffer([]byte(payload)))
	require.NoError(t, err)

	req = mux.SetURLVars(req, map[string]string{
		"keystoreID": testKeystoreID,
		"keyID":      testKeyID,
	})

	return req
}

func buildVerifyReq(t *testing.T, sig, msg string) *http.Request {
	t.Helper()

	payload := fmt.Sprintf(verifyReqFormat, sig, msg)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", bytes.NewBuffer([]byte(payload)))
	require.NoError(t, err)

	req = mux.SetURLVars(req, map[string]string{
		"keystoreID": testKeystoreID,
		"keyID":      testKeyID,
	})

	return req
}

func buildEncryptReq(t *testing.T, message, aad string) *http.Request {
	t.Helper()

	payload := fmt.Sprintf(encryptReqFormat, message, aad)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", bytes.NewBuffer([]byte(payload)))
	require.NoError(t, err)

	req = mux.SetURLVars(req, map[string]string{
		"keystoreID": testKeystoreID,
		"keyID":      testKeyID,
	})

	return req
}

func buildDecryptReq(t *testing.T, cipherText, aad, nonce string) *http.Request {
	t.Helper()

	payload := fmt.Sprintf(decryptReqFormat, cipherText, aad, nonce)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", bytes.NewBuffer([]byte(payload)))
	require.NoError(t, err)

	req = mux.SetURLVars(req, map[string]string{
		"keystoreID": testKeystoreID,
		"keyID":      testKeyID,
	})

	return req
}

func buildComputeMACReq(t *testing.T, data string) *http.Request {
	t.Helper()

	payload := fmt.Sprintf(computeMACReqFormat, data)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", bytes.NewBuffer([]byte(payload)))
	require.NoError(t, err)

	req = mux.SetURLVars(req, map[string]string{
		"keystoreID": testKeystoreID,
		"keyID":      testKeyID,
	})

	return req
}

func buildVerifyMACReq(t *testing.T, mac, data string) *http.Request {
	t.Helper()

	payload := fmt.Sprintf(verifyMACReqFormat, mac, data)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", bytes.NewBuffer([]byte(payload)))
	require.NoError(t, err)

	req = mux.SetURLVars(req, map[string]string{
		"keystoreID": testKeystoreID,
		"keyID":      testKeyID,
	})

	return req
}

type options struct {
	authService         authService
	kmsService          kms.Service
	cryptoBox           arieskms.CryptoBox
	cryptoBoxCreatorErr error
	logger              log.Logger
	tracer              trace.Tracer
}

type optionFn func(opts *options)

func newConfig(opts ...optionFn) *operation.Config {
	cOpts := &options{
		authService: &mockAuthService{},
		kmsService:  mockKMSService(),
		cryptoBox:   &mockCryptoBox{},
		logger:      &mocklogger.MockLogger{},
		tracer:      oteltest.NewTracerProvider().Tracer("test"),
	}

	for i := range opts {
		opts[i](cOpts)
	}

	cryptoBoxCreator := func(keyManager arieskms.KeyManager) (arieskms.CryptoBox, error) {
		if cOpts.cryptoBoxCreatorErr != nil {
			return nil, cOpts.cryptoBoxCreatorErr
		}

		return cOpts.cryptoBox, nil
	}

	config := &operation.Config{
		AuthService:      cOpts.authService,
		KMSService:       cOpts.kmsService,
		CryptoBoxCreator: cryptoBoxCreator,
		Logger:           cOpts.logger,
		Tracer:           cOpts.tracer,
	}

	return config
}

func mockKMSService() *mockkms.MockService {
	return &mockkms.MockService{
		CreateKeystoreValue:  &kms.KeystoreData{ID: testKeystoreID},
		ResolveKeystoreValue: &keystore.MockKeystore{CreateKeyValue: testKeyID},
		GetKeystoreDataValue: &kms.KeystoreData{ID: testKeystoreID},
	}
}

func withAuthService(svc authService) optionFn {
	return func(o *options) {
		o.authService = svc
	}
}

func withKMSService(svc kms.Service) optionFn {
	return func(o *options) {
		o.kmsService = svc
	}
}

func withCryptoBox(cb arieskms.CryptoBox) optionFn {
	return func(o *options) {
		o.cryptoBox = cb
	}
}

func withCryptoBoxCreatorErr(err error) optionFn {
	return func(o *options) {
		o.cryptoBoxCreatorErr = err
	}
}

func withLogger(l log.Logger) optionFn {
	return func(o *options) {
		o.logger = l
	}
}

type authService interface {
	CreateDIDKey(context.Context) (string, error)
	NewCapability(context.Context, ...zcapld.CapabilityOption) (*zcapld.Capability, error)
	KMS() arieskms.KeyManager
	Crypto() crypto.Crypto
	Resolve(string) (*zcapld.Capability, error)
}

type mockAuthService struct {
	createDIDKeyFunc func(context.Context) (string, error)
	newCapabilityVal *zcapld.Capability
	newCapabilityErr error
	keyManager       arieskms.KeyManager
	crpto            crypto.Crypto
	resolveVal       *zcapld.Capability
	resolveErr       error
}

func (m *mockAuthService) CreateDIDKey(ctx context.Context) (string, error) {
	if m.createDIDKeyFunc != nil {
		return m.createDIDKeyFunc(ctx)
	}

	return "", nil
}

func (m *mockAuthService) NewCapability(context.Context, ...zcapld.CapabilityOption) (*zcapld.Capability, error) {
	return m.newCapabilityVal, m.newCapabilityErr
}

func (m *mockAuthService) KMS() arieskms.KeyManager {
	return m.keyManager
}

func (m *mockAuthService) Crypto() crypto.Crypto {
	return m.crpto
}

func (m *mockAuthService) Resolve(string) (*zcapld.Capability, error) {
	return m.resolveVal, m.resolveErr
}

type mockCryptoBox struct {
	EasyValue     []byte
	EasyOpenValue []byte
	SealOpenValue []byte
	EasyErr       error
	EasyOpenErr   error
	SealOpenErr   error
}

// Easy seals a message with a provided nonce.
func (m *mockCryptoBox) Easy(payload, nonce, theirPub []byte, myKID string) ([]byte, error) {
	if m.EasyErr != nil {
		return nil, m.EasyErr
	}

	return m.EasyValue, nil
}

// EasyOpen unseals a message sealed with Easy, where the nonce is provided.
func (m *mockCryptoBox) EasyOpen(cipherText, nonce, theirPub, myPub []byte) ([]byte, error) {
	if m.EasyOpenErr != nil {
		return nil, m.EasyOpenErr
	}

	return m.EasyOpenValue, nil
}

func (m *mockCryptoBox) Seal(payload, theirEncPub []byte, randSource io.Reader) ([]byte, error) {
	panic("not supported")
}

// SealOpen decrypts a payload encrypted with Seal.
func (m *mockCryptoBox) SealOpen(cipherText, myPub []byte) ([]byte, error) {
	if m.SealOpenErr != nil {
		return nil, m.SealOpenErr
	}

	return m.SealOpenValue, nil
}
