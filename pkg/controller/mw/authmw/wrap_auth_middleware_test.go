/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package authmw_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/kms/pkg/controller/mw/authmw"
)

func TestWrapMiddleware(t *testing.T) {
	t.Run("should return 401 Unauthorized by default", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		next := NewMockHTTPHandler(ctrl)
		next.EXPECT().ServeHTTP(gomock.Any(), gomock.Any()).Times(0)

		auth := authmw.Wrap()(next)

		req, err := http.NewRequestWithContext(context.Background(), "", "", http.NoBody)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		auth.ServeHTTP(rr, req)

		require.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("should call next handler if request is authorized", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		next := NewMockHTTPHandler(ctrl)
		next.EXPECT().ServeHTTP(gomock.Any(), gomock.Any()).Times(1)

		mw := NewMockMiddleware(ctrl)
		mw.EXPECT().Accept(gomock.Any()).Return(true)
		mw.EXPECT().Middleware().Return(func(h http.Handler) http.Handler {
			return h
		})

		auth := authmw.Wrap(mw)(next)

		req, err := http.NewRequestWithContext(context.Background(), "", "", http.NoBody)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		auth.ServeHTTP(rr, req)

		require.Equal(t, http.StatusOK, rr.Code)
	})
}
