/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package prometheus_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/kms/pkg/metrics/prometheus"
)

func TestMetrics(t *testing.T) {
	m := prometheus.GetMetrics()
	require.NotNil(t, m)

	t.Run("", func(t *testing.T) {
		require.NotPanics(t, func() { m.ResolveKeystoreTime(time.Second) })
	})
}
