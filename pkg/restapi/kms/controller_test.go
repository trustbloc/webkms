/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/hub-kms/pkg/restapi/kms/operation"
)

func TestNew(t *testing.T) {
	controller := New(operation.NewMockProvider())
	require.NotNil(t, controller)
}

func TestGetOperations(t *testing.T) {
	controller := New(operation.NewMockProvider())
	require.NotNil(t, controller)

	ops := controller.GetOperations()

	require.Equal(t, 2, len(ops))
}
