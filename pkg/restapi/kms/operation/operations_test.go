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

	mockkeystore "github.com/trustbloc/hub-kms/pkg/internal/mock/keystore"
	mockkms "github.com/trustbloc/hub-kms/pkg/internal/mock/kms"
	"github.com/trustbloc/hub-kms/pkg/keystore"
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
)

func TestNew(t *testing.T) {
	op := operation.New(newConfig())
	require.NotNil(t, op)
}

func TestCreateKeystoreHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		srv := mockkeystore.NewMockService()
		srv.CreateKeystoreValue = &keystore.Keystore{ID: testKeystoreID}

		op := operation.New(newConfig(withKeystoreService(srv), withEDV(),
			withAuthService(&mockAuthService{}))) // TODO(#53): Improve reliability
		handler := getHandler(t, op, keystoresEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildCreateKeystoreReq(t))

		require.Equal(t, http.StatusCreated, rr.Code)
		require.NotEmpty(t, rr.Header().Get("Location"))
	})

	t.Run("Error from create did key", func(t *testing.T) {
		srv := mockkeystore.NewMockService()
		srv.CreateKeystoreValue = &keystore.Keystore{ID: testKeystoreID}

		op := operation.New(newConfig(withKeystoreService(srv), withEDV(),
			withAuthService(&mockAuthService{createDIDKeyFunc: func() (string, error) {
				return "", fmt.Errorf("failed to create did key")
			}}))) // TODO(#53): Improve reliability
		handler := getHandler(t, op, keystoresEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildCreateKeystoreReq(t))

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to create did key")
	})

	t.Run("Received bad request", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", bytes.NewBuffer([]byte("")))
		require.NoError(t, err)

		op := operation.New(newConfig())
		handler := getHandler(t, op, keystoresEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request: EOF")
	})

	t.Run("Failed to create a keystore", func(t *testing.T) {
		srv := mockkeystore.NewMockService()
		srv.CreateErr = errors.New("create keystore error")

		op := operation.New(newConfig(withKeystoreService(srv)))
		handler := getHandler(t, op, keystoresEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildCreateKeystoreReq(t))

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to create a keystore: create keystore error")
	})

	t.Run("internal server error if cannot create zcap", func(t *testing.T) {
		srv := mockkeystore.NewMockService()
		srv.CreateKeystoreValue = &keystore.Keystore{ID: testKeystoreID}

		op := operation.New(newConfig(
			withKeystoreService(srv),
			withAuthService(&mockAuthService{newCapabilityErr: errors.New("test")})),
		)
		handler := getHandler(t, op, keystoresEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildCreateKeystoreReq(t))

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to create zcap")
	})
}

func TestUpdateCapabilityHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		srv := mockkeystore.NewMockService()
		srv.GetKeystoreValue = &keystore.Keystore{ID: testKeystoreID}

		op := operation.New(newConfig(withKeystoreService(srv)))
		handler := getHandler(t, op, capabilityEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildUpdateCapabilityReq(t, []byte("{}")))

		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("test error from get key store", func(t *testing.T) {
		srv := mockkeystore.NewMockService()
		srv.GetErr = fmt.Errorf("failed to get key store")

		op := operation.New(newConfig(withKeystoreService(srv)))
		handler := getHandler(t, op, capabilityEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildUpdateCapabilityReq(t, []byte("{}")))

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to get key store")
	})

	t.Run("test error from store key store", func(t *testing.T) {
		srv := mockkeystore.NewMockService()
		srv.GetKeystoreValue = &keystore.Keystore{ID: testKeystoreID}
		srv.SaveErr = fmt.Errorf("failed to save key store")

		op := operation.New(newConfig(withKeystoreService(srv)))
		handler := getHandler(t, op, capabilityEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildUpdateCapabilityReq(t, []byte("{}")))

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to save key store")
	})

	t.Run("test empty capability", func(t *testing.T) {
		srv := mockkeystore.NewMockService()
		srv.GetKeystoreValue = &keystore.Keystore{ID: testKeystoreID}

		op := operation.New(newConfig(withKeystoreService(srv)))
		handler := getHandler(t, op, capabilityEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildUpdateCapabilityReq(t, nil))

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "edvCapability is empty")
	})
}

func TestCreateKeyHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		op := operation.New(newConfig())
		handler := getHandler(t, op, keysEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildCreateKeyReq(t))

		require.Equal(t, http.StatusCreated, rr.Code)
		require.NotEmpty(t, rr.Header().Get("Location"))
	})

	t.Run("Received bad request", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", bytes.NewBuffer([]byte("")))
		require.NoError(t, err)

		op := operation.New(newConfig())
		handler := getHandler(t, op, keysEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request: EOF")
	})

	t.Run("Failed to create a KMS service", func(t *testing.T) {
		op := operation.New(newConfig(withKMSServiceCreatorErr(errors.New("kms service creator error"))))
		handler := getHandler(t, op, keysEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildCreateKeyReq(t))

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to create a KMS service: kms service creator error")
	})

	t.Run("Failed to create a key", func(t *testing.T) {
		srv := mockkms.NewMockService()
		srv.CreateKeyErr = errors.New("create key error")

		op := operation.New(newConfig(withKMSService(srv)))
		handler := getHandler(t, op, keysEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildCreateKeyReq(t))

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to create a key: create key error")
	})
}

func TestExportKeyHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		srv := mockkms.NewMockService()
		srv.ExportKeyValue = []byte("public key bytes")

		op := operation.New(newConfig(withKMSService(srv)))
		handler := getHandler(t, op, exportEndpoint, http.MethodGet)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildExportKeyReq(t))

		require.Equal(t, http.StatusOK, rr.Code)
		require.Contains(t, rr.Body.String(), base64.URLEncoding.EncodeToString([]byte("public key bytes")))
	})

	t.Run("Failed to create a KMS service", func(t *testing.T) {
		op := operation.New(newConfig(withKMSServiceCreatorErr(errors.New("kms service creator error"))))
		handler := getHandler(t, op, exportEndpoint, http.MethodGet)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildExportKeyReq(t))

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to create a KMS service: kms service creator error")
	})

	t.Run("Failed to export a public key", func(t *testing.T) {
		srv := mockkms.NewMockService()
		srv.ExportKeyErr = errors.New("export key error")

		op := operation.New(newConfig(withKMSService(srv)))
		handler := getHandler(t, op, exportEndpoint, http.MethodGet)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildExportKeyReq(t))

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to export a public key: export key error")
	})
}

func TestSignHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		srv := mockkms.NewMockService()
		srv.SignValue = []byte("signature")

		op := operation.New(newConfig(withKMSService(srv)))
		handler := getHandler(t, op, signEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildSignReq(t, base64.URLEncoding.EncodeToString([]byte("test message"))))

		require.Equal(t, http.StatusOK, rr.Code)
		require.Contains(t, rr.Body.String(), base64.URLEncoding.EncodeToString([]byte("signature")))
	})

	t.Run("Received bad request: EOF", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", bytes.NewBuffer([]byte("")))
		require.NoError(t, err)

		op := operation.New(newConfig())
		handler := getHandler(t, op, signEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request: EOF")
	})

	t.Run("Received bad request: bad encoded message", func(t *testing.T) {
		op := operation.New(newConfig())
		handler := getHandler(t, op, signEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildSignReq(t, "!message"))

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request")
	})

	t.Run("Failed to create a KMS service", func(t *testing.T) {
		op := operation.New(newConfig(withKMSServiceCreatorErr(errors.New("kms service creator error"))))
		handler := getHandler(t, op, signEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildSignReq(t, base64.URLEncoding.EncodeToString([]byte("test message"))))

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to create a KMS service: kms service creator error")
	})

	t.Run("Failed to sign a message", func(t *testing.T) {
		srv := mockkms.NewMockService()
		srv.SignErr = errors.New("sign error")

		op := operation.New(newConfig(withKMSService(srv)))
		handler := getHandler(t, op, signEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildSignReq(t, base64.URLEncoding.EncodeToString([]byte("test message"))))

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to sign a message: sign error")
	})
}

func TestVerifyHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		op := operation.New(newConfig())
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

		op := operation.New(newConfig())
		handler := getHandler(t, op, verifyEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request: EOF")
	})

	t.Run("Received bad request: bad encoded signature", func(t *testing.T) {
		op := operation.New(newConfig())
		handler := getHandler(t, op, verifyEndpoint, http.MethodPost)

		msg := base64.URLEncoding.EncodeToString([]byte("test message"))
		req := buildVerifyReq(t, "!signature", msg)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request")
	})

	t.Run("Received bad request: bad encoded message", func(t *testing.T) {
		op := operation.New(newConfig())
		handler := getHandler(t, op, verifyEndpoint, http.MethodPost)

		sig := base64.URLEncoding.EncodeToString([]byte("test signature"))
		req := buildVerifyReq(t, sig, "!message")

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request")
	})

	t.Run("Failed to create a KMS service", func(t *testing.T) {
		op := operation.New(newConfig(withKMSServiceCreatorErr(errors.New("kms service creator error"))))
		handler := getHandler(t, op, verifyEndpoint, http.MethodPost)

		sig := base64.URLEncoding.EncodeToString([]byte("test signature"))
		msg := base64.URLEncoding.EncodeToString([]byte("test message"))
		req := buildVerifyReq(t, sig, msg)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to create a KMS service: kms service creator error")
	})

	t.Run("Failed to verify a message: verify error", func(t *testing.T) {
		srv := mockkms.NewMockService()
		srv.VerifyErr = errors.New("verify error")

		op := operation.New(newConfig(withKMSService(srv)))
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
		srv := mockkms.NewMockService()
		srv.EncryptValue = []byte("cipher text")

		op := operation.New(newConfig(withKMSService(srv)))
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

		op := operation.New(newConfig())
		handler := getHandler(t, op, encryptEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request: EOF")
	})

	t.Run("Received bad request: bad encoded message", func(t *testing.T) {
		op := operation.New(newConfig())
		handler := getHandler(t, op, encryptEndpoint, http.MethodPost)

		aad := base64.URLEncoding.EncodeToString([]byte("additional data"))
		req := buildEncryptReq(t, "!message", aad)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request")
	})

	t.Run("Received bad request: bad encoded aad", func(t *testing.T) {
		op := operation.New(newConfig())
		handler := getHandler(t, op, encryptEndpoint, http.MethodPost)

		msg := base64.URLEncoding.EncodeToString([]byte("test message"))
		req := buildEncryptReq(t, msg, "!aad")

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request")
	})

	t.Run("Failed to create a KMS service", func(t *testing.T) {
		op := operation.New(newConfig(withKMSServiceCreatorErr(errors.New("kms service creator error"))))
		handler := getHandler(t, op, encryptEndpoint, http.MethodPost)

		msg := base64.URLEncoding.EncodeToString([]byte("test message"))
		aad := base64.URLEncoding.EncodeToString([]byte("additional data"))
		req := buildEncryptReq(t, msg, aad)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to create a KMS service: kms service creator error")
	})

	t.Run("Failed to encrypt a message", func(t *testing.T) {
		srv := mockkms.NewMockService()
		srv.EncryptErr = errors.New("encrypt error")

		op := operation.New(newConfig(withKMSService(srv)))
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
		srv := mockkms.NewMockService()
		srv.DecryptValue = []byte("plain text")

		op := operation.New(newConfig(withKMSService(srv)))
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

		op := operation.New(newConfig())
		handler := getHandler(t, op, decryptEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request: EOF")
	})

	t.Run("Received bad request: bad encoded cipher text", func(t *testing.T) {
		op := operation.New(newConfig())
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
		op := operation.New(newConfig())
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
		op := operation.New(newConfig())
		handler := getHandler(t, op, decryptEndpoint, http.MethodPost)

		cipherText := base64.URLEncoding.EncodeToString([]byte("test cipher text"))
		aad := base64.URLEncoding.EncodeToString([]byte("additional data"))
		req := buildDecryptReq(t, cipherText, aad, "!nonce")

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request")
	})

	t.Run("Failed to create a KMS service", func(t *testing.T) {
		op := operation.New(newConfig(withKMSServiceCreatorErr(errors.New("kms service creator error"))))
		handler := getHandler(t, op, decryptEndpoint, http.MethodPost)

		cipherText := base64.URLEncoding.EncodeToString([]byte("test cipher text"))
		aad := base64.URLEncoding.EncodeToString([]byte("additional data"))
		nonce := base64.URLEncoding.EncodeToString([]byte("test nonce"))
		req := buildDecryptReq(t, cipherText, aad, nonce)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to create a KMS service: kms service creator error")
	})

	t.Run("Failed to decrypt a message", func(t *testing.T) {
		srv := mockkms.NewMockService()
		srv.DecryptErr = errors.New("decrypt error")

		op := operation.New(newConfig(withKMSService(srv)))
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
		srv := mockkms.NewMockService()
		srv.ComputeMACValue = []byte("mac")

		op := operation.New(newConfig(withKMSService(srv)))
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

		op := operation.New(newConfig())
		handler := getHandler(t, op, computeMACEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request: EOF")
	})

	t.Run("Received bad request: bad encoded data", func(t *testing.T) {
		op := operation.New(newConfig())
		handler := getHandler(t, op, computeMACEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildComputeMACReq(t, "!data"))

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request")
	})

	t.Run("Failed to create a KMS service", func(t *testing.T) {
		op := operation.New(newConfig(withKMSServiceCreatorErr(errors.New("kms service creator error"))))
		handler := getHandler(t, op, computeMACEndpoint, http.MethodPost)

		data := base64.URLEncoding.EncodeToString([]byte("test data"))
		req := buildComputeMACReq(t, data)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to create a KMS service: kms service creator error")
	})

	t.Run("Failed to compute MAC", func(t *testing.T) {
		srv := mockkms.NewMockService()
		srv.ComputeMACErr = errors.New("compute mac error")

		op := operation.New(newConfig(withKMSService(srv)))
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
		srv := mockkms.NewMockService()
		srv.ComputeMACValue = []byte("mac")

		op := operation.New(newConfig(withKMSService(srv)))
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

		op := operation.New(newConfig())
		handler := getHandler(t, op, verifyMACEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request: EOF")
	})

	t.Run("Received bad request: bad encoded mac", func(t *testing.T) {
		op := operation.New(newConfig())
		handler := getHandler(t, op, verifyMACEndpoint, http.MethodPost)

		data := base64.URLEncoding.EncodeToString([]byte("test data"))
		req := buildVerifyMACReq(t, "!mac", data)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request")
	})

	t.Run("Received bad request: bad encoded data", func(t *testing.T) {
		op := operation.New(newConfig())
		handler := getHandler(t, op, verifyMACEndpoint, http.MethodPost)

		mac := base64.URLEncoding.EncodeToString([]byte("mac"))
		req := buildVerifyMACReq(t, mac, "!data")

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request")
	})

	t.Run("Failed to create a KMS service", func(t *testing.T) {
		op := operation.New(newConfig(withKMSServiceCreatorErr(errors.New("kms service creator error"))))
		handler := getHandler(t, op, verifyMACEndpoint, http.MethodPost)

		mac := base64.URLEncoding.EncodeToString([]byte("mac"))
		data := base64.URLEncoding.EncodeToString([]byte("test data"))
		req := buildVerifyMACReq(t, mac, data)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to create a KMS service: kms service creator error")
	})

	t.Run("Failed to verify MAC", func(t *testing.T) {
		srv := mockkms.NewMockService()
		srv.VerifyMACErr = errors.New("verify mac error")

		op := operation.New(newConfig(withKMSService(srv)))
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
	srv := mockkms.NewMockService()
	srv.SignValue = []byte("signature")

	logger := &mocklogger.MockLogger{}

	op := operation.New(newConfig(withKMSService(srv), withLogger(logger)))
	handler := getHandler(t, op, signEndpoint, http.MethodPost)
	req := buildSignReq(t, base64.URLEncoding.EncodeToString([]byte("test message")))

	rr := failingResponseWriter{httptest.NewRecorder()}
	handler.Handle().ServeHTTP(rr, req)

	require.Empty(t, rr.Body.String())
	require.Contains(t, logger.ErrorLogContents, "Unable to send a response")
}

func TestFailToWriteErrorResponse(t *testing.T) {
	srv := mockkms.NewMockService()
	srv.CreateKeyErr = errors.New("create key error")

	logger := &mocklogger.MockLogger{}

	op := operation.New(newConfig(withKMSService(srv), withLogger(logger)))
	handler := getHandler(t, op, keysEndpoint, http.MethodPost)
	req := buildCreateKeyReq(t)

	rr := failingResponseWriter{httptest.NewRecorder()}
	handler.Handle().ServeHTTP(rr, req)

	require.Empty(t, rr.Body.String())
	require.Contains(t, logger.ErrorLogContents, "Unable to send an error message")
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
	keystoreService      keystore.Service
	kmsService           kms.Service
	logger               log.Logger
	kmsServiceCreatorErr error
	useEDV               bool
	authService          authService
}

type optionFn func(opts *options)

func newConfig(opts ...optionFn) *operation.Config {
	cOpts := &options{
		keystoreService: mockkeystore.NewMockService(),
		kmsService:      mockkms.NewMockService(),
		logger:          &mocklogger.MockLogger{},
		authService:     &mockAuthService{},
	}

	for i := range opts {
		opts[i](cOpts)
	}

	config := &operation.Config{
		KeystoreService:   cOpts.keystoreService,
		KMSServiceCreator: func(_ *http.Request) (kms.Service, error) { return cOpts.kmsService, nil },
		Logger:            cOpts.logger,
		UseEDV:            cOpts.useEDV,
		AuthService:       cOpts.authService,
	}

	if cOpts.kmsServiceCreatorErr != nil {
		config.KMSServiceCreator = func(_ *http.Request) (kms.Service, error) {
			return nil, cOpts.kmsServiceCreatorErr
		}
	}

	return config
}

func withKeystoreService(srv keystore.Service) optionFn {
	return func(o *options) {
		o.keystoreService = srv
	}
}

func withKMSService(srv kms.Service) optionFn {
	return func(o *options) {
		o.kmsService = srv
	}
}

func withLogger(l log.Logger) optionFn {
	return func(o *options) {
		o.logger = l
	}
}

func withKMSServiceCreatorErr(err error) optionFn {
	return func(o *options) {
		o.kmsServiceCreatorErr = err
	}
}

func withEDV() optionFn {
	return func(o *options) {
		o.useEDV = true
	}
}

func withAuthService(service authService) optionFn {
	return func(o *options) {
		o.authService = service
	}
}

type authService interface {
	CreateDIDKey() (string, error)
	NewCapability(options ...zcapld.CapabilityOption) (*zcapld.Capability, error)
	KMS() arieskms.KeyManager
	Crypto() crypto.Crypto
	Resolve(string) (*zcapld.Capability, error)
}

type mockAuthService struct {
	createDIDKeyFunc func() (string, error)
	newCapabilityVal *zcapld.Capability
	newCapabilityErr error
	keyManager       arieskms.KeyManager
	crpto            crypto.Crypto
	resolveVal       *zcapld.Capability
	resolveErr       error
}

func (m *mockAuthService) CreateDIDKey() (string, error) {
	if m.createDIDKeyFunc != nil {
		return m.createDIDKeyFunc()
	}

	return "", nil
}

func (m *mockAuthService) NewCapability(options ...zcapld.CapabilityOption) (*zcapld.Capability, error) {
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
