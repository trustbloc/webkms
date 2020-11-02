/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/hub-kms/pkg/kms"
)

func TestNewServiceError(t *testing.T) {
	serviceErr := kms.NewServiceError("test message", errors.New("error"))

	require.NotNil(t, serviceErr)
}

func TestError(t *testing.T) {
	t.Run("service error with wrapped error", func(t *testing.T) {
		serviceErr := kms.NewServiceError("test message", errors.New("error"))

		msg := serviceErr.Error()

		require.Equal(t, "test message: error", msg)
	})

	t.Run("service error without wrapped error", func(t *testing.T) {
		serviceErr := kms.NewServiceError("test message", nil)

		msg := serviceErr.Error()

		require.Equal(t, "test message", msg)
	})
}

func TestUnwrap(t *testing.T) {
	serviceErr := kms.NewServiceError("test message", errors.New("error"))

	err := serviceErr.Unwrap()

	require.EqualError(t, err, "error")
}

func TestUserErrorMessage(t *testing.T) {
	t.Run("service error", func(t *testing.T) {
		serviceErr := kms.NewServiceError("test message", errors.New("error"))

		msg := kms.UserErrorMessage(serviceErr)

		require.Equal(t, "test message", msg)
	})

	t.Run("other error", func(t *testing.T) {
		msg := kms.UserErrorMessage(errors.New("other error"))

		require.Equal(t, "other error", msg)
	})
}
