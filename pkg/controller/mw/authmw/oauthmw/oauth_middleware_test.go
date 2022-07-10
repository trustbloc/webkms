/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oauthmw_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/kms/pkg/controller/mw/authmw/oauthmw"
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
			"gnap token",
			[]string{"Authorization: GNAP token"},
			false,
		},
		{
			"bearer token",
			[]string{"Authorization: Bearer token"},
			true,
		},
		{
			"multiple authorization headers",
			[]string{"Authorization: GNAP token", "Authorization: Bearer token"},
			true,
		},
	}

	mw := oauthmw.Middleware{}

	for _, tt := range tests {
		req, err := http.NewRequestWithContext(context.Background(), "", "", http.NoBody)
		require.NoError(t, err)

		for _, header := range tt.headers {
			v := strings.Split(header, ":")

			req.Header.Add(v[0], v[1])
		}

		require.Equal(t, tt.accepted, mw.Accept(req))
	}
}

func TestMiddleware(t *testing.T) {
	t.Run("should call next handler", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		next := NewMockHTTPHandler(ctrl)
		next.EXPECT().ServeHTTP(gomock.Any(), gomock.Any()).Times(1)

		req, err := http.NewRequestWithContext(context.Background(), "", "", http.NoBody)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		mw := oauthmw.Middleware{}
		mw.Middleware()(next).ServeHTTP(rr, req)

		require.Equal(t, http.StatusOK, rr.Code)
	})
}
