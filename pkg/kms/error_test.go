/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestError(t *testing.T) {
	serviceErr := &serviceError{
		msg: "test message",
		err: errors.New("error"),
	}

	msg := serviceErr.Error()

	require.Equal(t, "test message: error", msg)
}

func TestUnwrap(t *testing.T) {
	serviceErr := &serviceError{
		msg: "test message",
		err: errors.New("error"),
	}

	err := serviceErr.Unwrap()

	require.EqualError(t, err, "error")
}

func TestErrorMessage(t *testing.T) {
	t.Run("service error", func(t *testing.T) {
		serviceErr := &serviceError{
			msg: "test message",
			err: errors.New("error"),
		}

		msg := ErrorMessage(serviceErr)

		require.Equal(t, "test message", msg)
	})

	t.Run("other error", func(t *testing.T) {
		msg := ErrorMessage(errors.New("other error"))

		require.Equal(t, "other error", msg)
	})
}
