/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package metrics_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/kms/pkg/metrics"
)

func TestMetrics(t *testing.T) {
	m := metrics.Get()
	require.NotNil(t, m)
	require.True(t, m == metrics.Get())

	t.Run("Metrics create", func(t *testing.T) {
		require.NotPanics(t, func() { m.CryptoSignTime(time.Second) })
		require.NotPanics(t, func() { m.DBPutTime("CouchDB", time.Second) })
		require.NotPanics(t, func() { m.DBGetTime("CouchDB", time.Second) })
		require.NotPanics(t, func() { m.DBGetTagsTime("CouchDB", time.Second) })
		require.NotPanics(t, func() { m.DBGetBulkTime("CouchDB", time.Second) })
		require.NotPanics(t, func() { m.DBQueryTime("CouchDB", time.Second) })
		require.NotPanics(t, func() { m.DBDeleteTime("CouchDB", time.Second) })
		require.NotPanics(t, func() { m.DBBatchTime("CouchDB", time.Second) })
		require.NotPanics(t, func() { m.KeyStoreGetKeyTime(time.Second) })
		require.NotPanics(t, func() { m.KeyStoreResolveTime(time.Second) })
		require.NotPanics(t, func() { m.AWSSecretLockEncryptTime(time.Second) })
		require.NotPanics(t, func() { m.AWSSecretLockDecryptTime(time.Second) })
		require.NotPanics(t, func() { m.KeySecretLockEncryptTime(time.Second) })
		require.NotPanics(t, func() { m.KeySecretLockDecryptTime(time.Second) })
	})
}
