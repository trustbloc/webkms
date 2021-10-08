/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package prometheus_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/kms/pkg/metrics/prometheus"
)

func TestMiddleware(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		handler := &mockHandler{}

		router := mux.NewRouter()
		router.Handle("/test", prometheus.Middleware(handler))

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/test", nil))

		require.True(t, handler.executed)
	})
}

type mockHandler struct {
	executed bool
}

func (h *mockHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)

	h.executed = true
}
