/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package restapi

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/hub-kms/pkg/keystore/mock"
)

func TestController_New(t *testing.T) {
	controller := New(mock.NewProvider())
	require.NotNil(t, controller)
}

func TestController_GetOperations(t *testing.T) {
	controller := New(mock.NewProvider())
	require.NotNil(t, controller)

	ops := controller.GetOperations()

	require.Equal(t, 2, len(ops))
}
