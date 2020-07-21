/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetRESTHandlers(t *testing.T) {
	op := New()
	require.Equal(t, 1, len(op.GetRESTHandlers()))
}

func TestHealthCheckHandler(t *testing.T) {
	op := New()

	r := &httptest.ResponseRecorder{}
	op.healthCheckHandler(r, nil)

	require.Equal(t, http.StatusOK, r.Code)
}
