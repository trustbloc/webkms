/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gnapmw_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
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

func TestMiddleware(t *testing.T) {
	t.Run("should call next handler if request is authorized", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		client := NewMockGNAPRSClient(ctrl)
		client.EXPECT().Introspect(gomock.Any()).Return(&gnap.IntrospectResponse{Active: true}, nil)

		mw := gnapmw.Middleware{Client: client, RSPubKey: &jwk.JWK{}}

		next := NewMockHTTPHandler(ctrl)
		next.EXPECT().ServeHTTP(gomock.Any(), gomock.Any()).Times(1)

		req, err := http.NewRequestWithContext(context.Background(), "", "", nil)
		require.NoError(t, err)

		req.Header.Add("Authorization", "GNAP token")

		rr := httptest.NewRecorder()

		mw.Middleware()(next).ServeHTTP(rr, req)

		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("should return 401 Unauthorized if no gnap token", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		client := NewMockGNAPRSClient(ctrl)
		client.EXPECT().Introspect(gomock.Any()).Times(0)

		mw := gnapmw.Middleware{Client: client, RSPubKey: &jwk.JWK{}}

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

		mw := gnapmw.Middleware{Client: client, RSPubKey: &jwk.JWK{}}

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

		mw := gnapmw.Middleware{Client: client, RSPubKey: &jwk.JWK{}}

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
