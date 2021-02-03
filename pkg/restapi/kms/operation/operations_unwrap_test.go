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
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/kms/pkg/internal/mock/keystore"
	mockkms "github.com/trustbloc/kms/pkg/internal/mock/kms"
)

func TestUnwrapHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		svc := mockKMSService()
		svc.UnwrapValue = []byte("unwrap key value")

		op := newOperation(t, newConfig(withKMSService(svc)))
		handler := getHandler(t, op, unwrapEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildUnwrapReq(t))

		require.Equal(t, http.StatusOK, rr.Code)
		require.Contains(t, rr.Body.String(), "key")
	})

	t.Run("Received bad request: EOF", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", bytes.NewBuffer([]byte("")))
		require.NoError(t, err)

		op := newOperation(t, newConfig())
		handler := getHandler(t, op, unwrapEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request: EOF")
	})

	t.Run("Failed to resolve a keystore", func(t *testing.T) {
		svc := &mockkms.MockService{ResolveKeystoreErr: errors.New("resolve keystore error")}

		op := newOperation(t, newConfig(withKMSService(svc)))
		handler := getHandler(t, op, unwrapEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildUnwrapReq(t))

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to resolve a keystore: resolve keystore error")
	})

	t.Run("Failed to get key handle", func(t *testing.T) {
		svc := mockKMSService()
		svc.ResolveKeystoreValue = &keystore.MockKeystore{GetKeyHandleErr: errors.New("get key handle error")}

		op := newOperation(t, newConfig(withKMSService(svc)))
		handler := getHandler(t, op, unwrapEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildUnwrapReq(t))

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to unwrap a key: get key handle error")
	})

	t.Run("Failed to unwrap a key", func(t *testing.T) {
		svc := mockKMSService()
		svc.UnwrapError = errors.New("unwrap key error")

		op := newOperation(t, newConfig(withKMSService(svc)))
		handler := getHandler(t, op, unwrapEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildUnwrapReq(t))

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to unwrap a key: unwrap key error")
	})
}

func TestUnwrapHandler_BadRequestEncoding(t *testing.T) {
	tests := []struct {
		name   string
		reqOpt unwrapReqOptionFn
	}{
		{"kid", withWrappedKID("invalid")},
		{"encryptedcek", withEncryptedCEK("invalid")},
		{"epk kid", withEpkKID("invalid")},
		{"epk x", withEpkX("invalid")},
		{"epk y", withEpkY("invalid")},
		{"epk curve", withEpkCurve("invalid")},
		{"epk type", withEpkType("invalid")},
		{"alg", withWrappedKeyAlg("invalid")},
		{"apu", withWrappedKeyAPU("invalid")},
		{"apv", withWrappedKeyAPV("invalid")},
	}

	for _, tt := range tests {
		opt := tt.reqOpt

		t.Run("Received bad request: bad encoded "+tt.name, func(t *testing.T) {
			srv := &mockkms.MockService{}
			srv.WrapValue = &crypto.RecipientWrappedKey{}

			op := newOperation(t, newConfig(withKMSService(srv)))
			handler := getHandler(t, op, unwrapEndpoint, http.MethodPost)

			rr := httptest.NewRecorder()
			handler.Handle().ServeHTTP(rr, buildUnwrapReq(t, opt))

			require.Equal(t, http.StatusBadRequest, rr.Code)
			require.Contains(t, rr.Body.String(), "Received bad request")
		})
	}
}

func buildUnwrapReq(t *testing.T, opts ...unwrapReqOptionFn) *http.Request {
	t.Helper()

	unwrapReqOpts := &unwrapReqOptions{
		kid:          base64.URLEncoding.EncodeToString([]byte("kid")),
		encryptedCEK: base64.URLEncoding.EncodeToString([]byte("encryptedCEK")),
		epkKID:       base64.URLEncoding.EncodeToString([]byte("kid")),
		epkX:         base64.URLEncoding.EncodeToString([]byte("x")),
		epkY:         base64.URLEncoding.EncodeToString([]byte("y")),
		epkCurve:     base64.URLEncoding.EncodeToString([]byte("curve")),
		epkType:      base64.URLEncoding.EncodeToString([]byte("type")),
		alg:          base64.URLEncoding.EncodeToString([]byte("alg")),
		apu:          base64.URLEncoding.EncodeToString([]byte("apu")),
		apv:          base64.URLEncoding.EncodeToString([]byte("apv")),
		senderKID:    "senderKID",
	}

	for i := range opts {
		opts[i](unwrapReqOpts)
	}

	epk := fmt.Sprintf(publicKeyFormat,
		unwrapReqOpts.epkKID,
		unwrapReqOpts.epkX,
		unwrapReqOpts.epkY,
		unwrapReqOpts.epkCurve,
		unwrapReqOpts.epkType,
	)

	wrappedKey := fmt.Sprintf(wrappedKeyFormat,
		unwrapReqOpts.kid,
		unwrapReqOpts.encryptedCEK,
		epk,
		unwrapReqOpts.alg,
		unwrapReqOpts.apu,
		unwrapReqOpts.apv,
	)

	payload := fmt.Sprintf(unwrapReqFormat,
		wrappedKey,
		unwrapReqOpts.senderKID,
	)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", bytes.NewBuffer([]byte(payload)))
	require.NoError(t, err)

	req = mux.SetURLVars(req, map[string]string{
		"keystoreID": testKeystoreID,
		"keyID":      testKeyID,
	})

	return req
}

type unwrapReqOptions struct {
	kid          string
	encryptedCEK string
	epkKID       string
	epkX         string
	epkY         string
	epkCurve     string
	epkType      string
	alg          string
	apu          string
	apv          string
	senderKID    string
}

type unwrapReqOptionFn func(opts *unwrapReqOptions)

func withWrappedKID(kid string) unwrapReqOptionFn {
	return func(opts *unwrapReqOptions) {
		opts.kid = kid
	}
}

func withEncryptedCEK(cek string) unwrapReqOptionFn {
	return func(opts *unwrapReqOptions) {
		opts.encryptedCEK = cek
	}
}

func withEpkKID(kid string) unwrapReqOptionFn {
	return func(opts *unwrapReqOptions) {
		opts.epkKID = kid
	}
}

func withEpkX(x string) unwrapReqOptionFn {
	return func(opts *unwrapReqOptions) {
		opts.epkX = x
	}
}

func withEpkY(y string) unwrapReqOptionFn {
	return func(opts *unwrapReqOptions) {
		opts.epkY = y
	}
}

func withEpkCurve(curve string) unwrapReqOptionFn {
	return func(opts *unwrapReqOptions) {
		opts.epkCurve = curve
	}
}

func withEpkType(typ string) unwrapReqOptionFn {
	return func(opts *unwrapReqOptions) {
		opts.epkType = typ
	}
}

func withWrappedKeyAlg(alg string) unwrapReqOptionFn {
	return func(opts *unwrapReqOptions) {
		opts.alg = alg
	}
}

func withWrappedKeyAPU(apu string) unwrapReqOptionFn {
	return func(opts *unwrapReqOptions) {
		opts.apu = apu
	}
}

func withWrappedKeyAPV(apv string) unwrapReqOptionFn {
	return func(opts *unwrapReqOptions) {
		opts.apv = apv
	}
}
