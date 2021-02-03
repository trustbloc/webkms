/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/log/mocklogger"

	"github.com/trustbloc/kms/pkg/restapi/healthcheck/operation"
)

type failingResponseWriter struct {
	*httptest.ResponseRecorder
}

func (failingResponseWriter) Write(_ []byte) (int, error) {
	return 0, errors.New("write error")
}

func TestGetRESTHandlers(t *testing.T) {
	op := operation.New(&mocklogger.MockLogger{})
	require.Equal(t, 1, len(op.GetRESTHandlers()))
}

func TestHealthCheckHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "", nil)
		require.NoError(t, err)

		op := operation.New(&mocklogger.MockLogger{})
		handler := getHealthCheckHandler(t, op)

		rr := httptest.NewRecorder()
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Fail to write response", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "", nil)
		require.NoError(t, err)

		logger := &mocklogger.MockLogger{}
		op := operation.New(logger)
		handler := getHealthCheckHandler(t, op)

		rr := failingResponseWriter{httptest.NewRecorder()}
		handler.Handle().ServeHTTP(rr, req)

		require.Equal(t, "healthcheck response failure: write error\n", logger.ErrorLogContents)
	})
}

func getHealthCheckHandler(t *testing.T, op *operation.Operation) operation.Handler {
	t.Helper()

	handlers := op.GetRESTHandlers()
	require.NotEmpty(t, handlers)

	const healthCheckEndpoint = "/healthcheck"

	for _, h := range handlers {
		if h.Path() == healthCheckEndpoint {
			return h
		}
	}

	require.Fail(t, "unable to find handler")

	return nil
}
