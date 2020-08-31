/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/hub-kms/pkg/internal/mock/log"
)

type failingResponseWriter struct {
	*httptest.ResponseRecorder
}

func (failingResponseWriter) Write(_ []byte) (int, error) {
	return 0, errors.New("write error")
}

func TestGetRESTHandlers(t *testing.T) {
	op := New(&log.MockLogger{})
	require.Equal(t, 1, len(op.GetRESTHandlers()))
}

func TestHealthCheckHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		op := New(&log.MockLogger{})

		r := &httptest.ResponseRecorder{}
		op.healthCheckHandler(r, nil)

		require.Equal(t, http.StatusOK, r.Code)
	})

	t.Run("Fail to write response", func(t *testing.T) {
		logger := &log.MockLogger{}
		op := New(logger)

		r := failingResponseWriter{httptest.NewRecorder()}
		op.healthCheckHandler(r, nil)

		require.Equal(t, "healthcheck response failure: write error", logger.ErrorText)
	})
}
