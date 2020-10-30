/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/hub-kms/pkg/internal/mock/operation"
	"github.com/trustbloc/hub-kms/pkg/restapi/kms"
)

func TestNew(t *testing.T) {
	controller := kms.New(operation.NewMockProvider())
	require.NotNil(t, controller)
}

func TestGetOperations(t *testing.T) {
	controller := kms.New(operation.NewMockProvider())
	require.NotNil(t, controller)

	ops := controller.GetOperations()

	require.Equal(t, 8, len(ops))
}
