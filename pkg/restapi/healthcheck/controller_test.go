/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package healthcheck_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/log/mocklogger"

	"github.com/trustbloc/hub-kms/pkg/restapi/healthcheck"
)

func TestNew(t *testing.T) {
	controller := healthcheck.New(&mocklogger.MockLogger{})
	require.NotNil(t, controller)
}

func TestGetOperations(t *testing.T) {
	controller := healthcheck.New(&mocklogger.MockLogger{})
	require.NotNil(t, controller)

	ops := controller.GetOperations()

	require.Equal(t, 1, len(ops))
}
