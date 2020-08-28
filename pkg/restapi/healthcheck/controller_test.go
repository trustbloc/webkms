/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package healthcheck

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/hub-kms/pkg/internal/mock/log"
)

func TestNew(t *testing.T) {
	controller := New(&log.MockLogger{})
	require.NotNil(t, controller)
}

func TestGetOperations(t *testing.T) {
	controller := New(&log.MockLogger{})
	require.NotNil(t, controller)

	ops := controller.GetOperations()

	require.Equal(t, 1, len(ops))
}
