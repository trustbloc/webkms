/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gnapmw_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"github.com/square/go-jose/v3"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/auth/spi/gnap"

	"github.com/trustbloc/kms/pkg/controller/mw/authmw/gnapmw"
)

func TestAccept(t *testing.T) {
	tests := []struct {
		name     string
		headers  []string
		accepted bool
	}{
		{
			"no authorization header",
			[]string{},
			false,
		},
		{
			"bearer token",
			[]string{"Authorization: Bearer token"},
			false,
		},
		{
			"gnap token",
			[]string{"Authorization: GNAP token"},
			true,
		},
		{
			"multiple authorization headers",
			[]string{"Authorization: GNAP token", "Authorization: Bearer token"},
			true,
		},
	}

	mw := gnapmw.Middleware{}

	for _, tt := range tests {
		req, err := http.NewRequestWithContext(context.Background(), "", "", nil)
		require.NoError(t, err)

		for _, header := range tt.headers {
			v := strings.Split(header, ":")

			req.Header.Add(v[0], v[1])
		}

		require.Equal(t, tt.accepted, mw.Accept(req))
	}
}

type gnapRSClientTest interface {
	Introspect(req *gnap.IntrospectRequest) (*gnap.IntrospectResponse, error)
}

func TestNewMiddlewareErrors(t *testing.T) {
	ctrl := gomock.NewController(t)

	tests := []struct {
		name           string
		errString      string
		client         gnapRSClientTest
		rsPubKey       *jwk.JWK
		createVerifier func(req *http.Request) gnapmw.GNAPVerifier
	}{
		{
			name:           "missing client",
			errString:      "gnap client is empty",
			rsPubKey:       &jwk.JWK{},
			createVerifier: func(req *http.Request) gnapmw.GNAPVerifier { return nil },
		},
		{
			name:           "missing public key",
			errString:      "public key is empty",
			client:         NewMockGNAPRSClient(ctrl),
			createVerifier: func(req *http.Request) gnapmw.GNAPVerifier { return nil },
		},
		{
			name:      "missing createVerifier function",
			errString: "createVerifier function is empty",
			client:    NewMockGNAPRSClient(ctrl),
			rsPubKey:  &jwk.JWK{},
		},
	}

	for _, tt := range tests {
		tc := tt

		t.Run(fmt.Sprintf("create middleware error due to %s", tc.name), func(t *testing.T) {
			mw, err := gnapmw.NewMiddleware(tc.client, tc.rsPubKey, tc.createVerifier, false)
			require.EqualError(t, err, tc.errString)
			require.Nil(t, mw)
		})
	}
}

func TestMiddleware(t *testing.T) {
	t.Run("should call next handler if request is authorized", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

		privJWK := &jwk.JWK{
			JSONWebKey: jose.JSONWebKey{
				Key:       privKey,
				KeyID:     "key1",
				Algorithm: "ES256",
			},
			Kty: "EC",
			Crv: "P-256",
		}

		pubJWK := jwk.JWK{
			JSONWebKey: privJWK.Public(),
			Kty:        "EC",
			Crv:        "P-256",
		}

		require.NoError(t, err)
		client := NewMockGNAPRSClient(ctrl)
		client.EXPECT().Introspect(gomock.Any()).Return(&gnap.IntrospectResponse{Active: true, Key: &gnap.ClientKey{
			JWK: pubJWK,
		}}, nil)

		mVerifier := NewMockGNAPVerifier(ctrl)
		mVerifier.EXPECT().Verify(gomock.Any()).Times(1)

		mw, err := gnapmw.NewMiddleware(client, &pubJWK, func(req *http.Request) gnapmw.GNAPVerifier {
			return mVerifier
		}, false)
		require.NoError(t, err)

		next := NewMockHTTPHandler(ctrl)
		next.EXPECT().ServeHTTP(gomock.Any(), gomock.Any()).Times(1)

		req, err := http.NewRequestWithContext(context.Background(), "", "", nil)
		require.NoError(t, err)

		req.Header.Add("Authorization", "GNAP token")

		rr := httptest.NewRecorder()

		mw.Middleware()(next).ServeHTTP(rr, req)

		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("should call next handler if request is authorized "+
		"(GNAP token is second value in Authorization header)", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

		privJWK := &jwk.JWK{
			JSONWebKey: jose.JSONWebKey{
				Key:       privKey,
				KeyID:     "key1",
				Algorithm: "ES256",
			},
			Kty: "EC",
			Crv: "P-256",
		}

		pubJWK := jwk.JWK{
			JSONWebKey: privJWK.Public(),
			Kty:        "EC",
			Crv:        "P-256",
		}

		require.NoError(t, err)
		client := NewMockGNAPRSClient(ctrl)
		client.EXPECT().Introspect(gomock.Any()).Return(&gnap.IntrospectResponse{Active: true, Key: &gnap.ClientKey{
			JWK: pubJWK,
		}}, nil)

		mVerifier := NewMockGNAPVerifier(ctrl)
		mVerifier.EXPECT().Verify(gomock.Any()).Times(1)

		mw, err := gnapmw.NewMiddleware(client, &pubJWK, func(req *http.Request) gnapmw.GNAPVerifier {
			return mVerifier
		}, false)
		require.NoError(t, err)

		next := NewMockHTTPHandler(ctrl)
		next.EXPECT().ServeHTTP(gomock.Any(), gomock.Any()).Times(1)

		req, err := http.NewRequestWithContext(context.Background(), "", "", nil)
		require.NoError(t, err)

		req.Header.Add("Authorization", "Some other token")
		req.Header.Add("Authorization", "GNAP token")

		rr := httptest.NewRecorder()

		mw.Middleware()(next).ServeHTTP(rr, req)

		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("should return 401 Unauthorized if request is unauthorized due to signature error", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

		privJWK := &jwk.JWK{
			JSONWebKey: jose.JSONWebKey{
				Key:       privKey,
				KeyID:     "key1",
				Algorithm: "ES256",
			},
			Kty: "EC",
			Crv: "P-256",
		}

		pubJWK := jwk.JWK{
			JSONWebKey: privJWK.Public(),
			Kty:        "EC",
			Crv:        "P-256",
		}

		require.NoError(t, err)
		client := NewMockGNAPRSClient(ctrl)
		client.EXPECT().Introspect(gomock.Any()).Return(&gnap.IntrospectResponse{Active: true, Key: &gnap.ClientKey{
			JWK: pubJWK,
		}}, nil)

		mVerifier := NewMockGNAPVerifier(ctrl)
		mVerifier.EXPECT().Verify(gomock.Any()).Return(fmt.Errorf("verification error")).Times(1)

		mw, err := gnapmw.NewMiddleware(client, &pubJWK, func(req *http.Request) gnapmw.GNAPVerifier {
			return mVerifier
		}, false)
		require.NoError(t, err)

		next := NewMockHTTPHandler(ctrl)
		next.EXPECT().ServeHTTP(gomock.Any(), gomock.Any()).Times(0)

		req, err := http.NewRequestWithContext(context.Background(), "", "", nil)
		require.NoError(t, err)

		req.Header.Add("Authorization", "GNAP token")

		rr := httptest.NewRecorder()

		mw.Middleware()(next).ServeHTTP(rr, req)

		require.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("should return 401 Unauthorized if no gnap token", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		client := NewMockGNAPRSClient(ctrl)
		client.EXPECT().Introspect(gomock.Any()).Times(0)

		mVerifier := NewMockGNAPVerifier(ctrl)
		mVerifier.EXPECT().Verify(gomock.Any()).Times(0)

		mw, err := gnapmw.NewMiddleware(client, &jwk.JWK{}, func(req *http.Request) gnapmw.GNAPVerifier {
			return mVerifier
		}, false)
		require.NoError(t, err)

		next := NewMockHTTPHandler(ctrl)
		next.EXPECT().ServeHTTP(gomock.Any(), gomock.Any()).Times(0)

		req, err := http.NewRequestWithContext(context.Background(), "", "", nil)
		require.NoError(t, err)

		req.Header.Add("Authorization", "Bearer token")

		rr := httptest.NewRecorder()

		mw.Middleware()(next).ServeHTTP(rr, req)

		require.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("should return 500 StatusInternalServerError if introspect call fails", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		client := NewMockGNAPRSClient(ctrl)
		client.EXPECT().Introspect(gomock.Any()).Return(nil, errors.New("introspect error"))

		mVerifier := NewMockGNAPVerifier(ctrl)
		mVerifier.EXPECT().Verify(gomock.Any()).Times(0)

		mw, err := gnapmw.NewMiddleware(client, &jwk.JWK{}, func(req *http.Request) gnapmw.GNAPVerifier {
			return mVerifier
		}, false)
		require.NoError(t, err)

		next := NewMockHTTPHandler(ctrl)
		next.EXPECT().ServeHTTP(gomock.Any(), gomock.Any()).Times(0)

		req, err := http.NewRequestWithContext(context.Background(), "", "", nil)
		require.NoError(t, err)

		req.Header.Add("Authorization", "GNAP token")

		rr := httptest.NewRecorder()

		mw.Middleware()(next).ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
	})

	t.Run("should return 401 Unauthorized if token is inactive", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		client := NewMockGNAPRSClient(ctrl)
		client.EXPECT().Introspect(gomock.Any()).Return(&gnap.IntrospectResponse{Active: false}, nil)

		mVerifier := NewMockGNAPVerifier(ctrl)
		mVerifier.EXPECT().Verify(gomock.Any()).Times(0)

		mw, err := gnapmw.NewMiddleware(client, &jwk.JWK{}, func(req *http.Request) gnapmw.GNAPVerifier {
			return mVerifier
		}, false)
		require.NoError(t, err)

		next := NewMockHTTPHandler(ctrl)
		next.EXPECT().ServeHTTP(gomock.Any(), gomock.Any()).Times(0)

		req, err := http.NewRequestWithContext(context.Background(), "", "", nil)
		require.NoError(t, err)

		req.Header.Add("Authorization", "GNAP token")

		rr := httptest.NewRecorder()

		mw.Middleware()(next).ServeHTTP(rr, req)

		require.Equal(t, http.StatusUnauthorized, rr.Code)
	})
}
