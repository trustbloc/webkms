/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package errors_test

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	. "github.com/trustbloc/kms/pkg/controller/errors"
)

func TestStatusCodeFromError(t *testing.T) {
	const errMsg = "error"

	// http errors
	require.Equal(t, StatusCodeFromError(NewStatusInternalServerError(New(errMsg))), http.StatusInternalServerError)
	require.Equal(t, StatusCodeFromError(NewBadRequestError(New(errMsg))), http.StatusBadRequest)
	require.Equal(t, StatusCodeFromError(NewNotFoundError(New(errMsg))), http.StatusNotFound)

	// by default error has status InternalServerError
	require.Equal(t, StatusCodeFromError(New(errMsg)), http.StatusInternalServerError)

	// wrapped error
	require.Equal(t, StatusCodeFromError(fmt.Errorf("wrapped: %w", ErrValidation)), http.StatusBadRequest)
	require.True(t, errors.Is(fmt.Errorf("wrapped: %w", ErrValidation), ErrValidation))
	require.Equal(t, errors.Unwrap(NewBadRequestError(fmt.Errorf("wrapped: %w", ErrValidation))), ErrValidation)

	require.Equal(t, StatusCodeFromError(fmt.Errorf("wrapped: %w", ErrBadRequest)), http.StatusBadRequest)
	require.True(t, errors.Is(fmt.Errorf("wrapped: %w", ErrBadRequest), ErrBadRequest))
	require.Equal(t, errors.Unwrap(NewBadRequestError(fmt.Errorf("wrapped: %w", ErrBadRequest))), ErrBadRequest)

	require.Equal(t, StatusCodeFromError(fmt.Errorf("wrapped: %w", ErrNotFound)), http.StatusNotFound)
	require.True(t, errors.Is(fmt.Errorf("wrapped: %w", ErrNotFound), ErrNotFound))
	require.Equal(t, errors.Unwrap(NewBadRequestError(fmt.Errorf("wrapped: %w", ErrNotFound))), ErrNotFound)

	require.Equal(t, StatusCodeFromError(fmt.Errorf("wrapped: %w", ErrInternal)), http.StatusInternalServerError)
	require.True(t, errors.Is(fmt.Errorf("wrapped: %w", ErrInternal), ErrInternal))
	require.Equal(t, errors.Unwrap(NewBadRequestError(fmt.Errorf("wrapped: %w", ErrInternal))), ErrInternal)
}
