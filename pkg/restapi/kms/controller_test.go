/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/hub-kms/pkg/internal/mock/provider"
)

func TestNew(t *testing.T) {
	controller := New(provider.NewMockProvider())
	require.NotNil(t, controller)
}

func TestGetOperations(t *testing.T) {
	controller := New(provider.NewMockProvider())
	require.NotNil(t, controller)

	ops := controller.GetOperations()

	require.Equal(t, 2, len(ops))
}
