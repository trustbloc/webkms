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

	mockkms "github.com/trustbloc/kms/pkg/internal/mock/kms"
)

func TestWrapHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		srv := mockKMSService()
		srv.WrapValue = &crypto.RecipientWrappedKey{}

		op := newOperation(t, newConfig(withKMSService(srv)))
		handler := getHandler(t, op, wrapEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildWrapReq(t))

		require.Equal(t, http.StatusOK, rr.Code)
		require.Contains(t, rr.Body.String(), "wrappedKey")
	})

	t.Run("Received bad request: EOF", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", bytes.NewBuffer([]byte("")))
		require.NoError(t, err)

		op := newOperation(t, newConfig())
		handler := getHandler(t, op, wrapEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received bad request: EOF")
	})

	t.Run("Failed to wrap a key", func(t *testing.T) {
		svc := mockKMSService()
		svc.WrapError = errors.New("wrap key error")

		op := newOperation(t, newConfig(withKMSService(svc)))
		handler := getHandler(t, op, wrapEndpoint, http.MethodPost)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, buildWrapReq(t))

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "Failed to wrap a key: wrap key error")
	})
}

func TestWrapHandler_BadRequestEncoding(t *testing.T) {
	tests := []struct {
		name   string
		reqOpt wrapReqOptionFn
	}{
		{"cek", withCEK("invalid")},
		{"apu", withAPU("invalid")},
		{"apv", withAPV("invalid")},
		{"pub key kid", withPubKID("invalid")},
		{"pub key x", withPubX("invalid")},
		{"pub key y", withPubY("invalid")},
		{"pub key curve", withPubCurve("invalid")},
		{"pub key type", withPubType("invalid")},
	}

	for _, tt := range tests {
		opt := tt.reqOpt

		t.Run("Received bad request: bad encoded "+tt.name, func(t *testing.T) {
			srv := &mockkms.MockService{}
			srv.WrapValue = &crypto.RecipientWrappedKey{}

			op := newOperation(t, newConfig(withKMSService(srv)))
			handler := getHandler(t, op, wrapEndpoint, http.MethodPost)

			rr := httptest.NewRecorder()
			handler.Handle().ServeHTTP(rr, buildWrapReq(t, opt))

			require.Equal(t, http.StatusBadRequest, rr.Code)
			require.Contains(t, rr.Body.String(), "Received bad request")
		})
	}
}

func buildWrapReq(t *testing.T, opts ...wrapReqOptionFn) *http.Request {
	t.Helper()

	wrapReqOpts := &wrapReqOptions{
		cek:       base64.URLEncoding.EncodeToString([]byte("cek")),
		apu:       base64.URLEncoding.EncodeToString([]byte("apu")),
		apv:       base64.URLEncoding.EncodeToString([]byte("apv")),
		pubKID:    base64.URLEncoding.EncodeToString([]byte("kid")),
		pubX:      base64.URLEncoding.EncodeToString([]byte("x")),
		pubY:      base64.URLEncoding.EncodeToString([]byte("y")),
		pubCurve:  base64.URLEncoding.EncodeToString([]byte("curve")),
		pubType:   base64.URLEncoding.EncodeToString([]byte("type")),
		senderKID: "senderKID",
	}

	for i := range opts {
		opts[i](wrapReqOpts)
	}

	pubKey := fmt.Sprintf(publicKeyFormat,
		wrapReqOpts.pubKID,
		wrapReqOpts.pubX,
		wrapReqOpts.pubY,
		wrapReqOpts.pubCurve,
		wrapReqOpts.pubType,
	)

	payload := fmt.Sprintf(wrapReqFormat,
		wrapReqOpts.cek,
		wrapReqOpts.apu,
		wrapReqOpts.apv,
		pubKey,
		wrapReqOpts.senderKID,
	)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", bytes.NewBuffer([]byte(payload)))
	require.NoError(t, err)

	req = mux.SetURLVars(req, map[string]string{
		"keystoreID": testKeystoreID,
	})

	return req
}

type wrapReqOptions struct {
	cek       string
	apu       string
	apv       string
	pubKID    string
	pubX      string
	pubY      string
	pubCurve  string
	pubType   string
	senderKID string
}

type wrapReqOptionFn func(opts *wrapReqOptions)

func withCEK(cek string) wrapReqOptionFn {
	return func(opts *wrapReqOptions) {
		opts.cek = cek
	}
}

func withAPU(apu string) wrapReqOptionFn {
	return func(opts *wrapReqOptions) {
		opts.apu = apu
	}
}

func withAPV(apv string) wrapReqOptionFn {
	return func(opts *wrapReqOptions) {
		opts.apv = apv
	}
}

func withPubKID(kid string) wrapReqOptionFn {
	return func(opts *wrapReqOptions) {
		opts.pubKID = kid
	}
}

func withPubX(x string) wrapReqOptionFn {
	return func(opts *wrapReqOptions) {
		opts.pubX = x
	}
}

func withPubY(y string) wrapReqOptionFn {
	return func(opts *wrapReqOptions) {
		opts.pubY = y
	}
}

func withPubCurve(curve string) wrapReqOptionFn {
	return func(opts *wrapReqOptions) {
		opts.pubCurve = curve
	}
}

func withPubType(typ string) wrapReqOptionFn {
	return func(opts *wrapReqOptions) {
		opts.pubType = typ
	}
}
