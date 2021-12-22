/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package metrics_test

import (
	"testing"

	ariesmockstorage "github.com/hyperledger/aries-framework-go/component/storageutil/mock"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/kms/pkg/storage/metrics"
)

func TestProvider(t *testing.T) {
	s := metrics.Wrap(&ariesmockstorage.Provider{}, "CouchDB")
	require.NotNil(t, s)

	t.Run("open store", func(t *testing.T) {
		_, err := s.OpenStore("s1")
		require.NoError(t, err)
	})

	t.Run("get store config", func(t *testing.T) {
		_, err := s.GetStoreConfig("s1")
		require.NoError(t, err)
	})

	t.Run("set store config", func(t *testing.T) {
		require.NoError(t, s.SetStoreConfig("s1", storage.StoreConfiguration{}))
	})

	t.Run("get open stores", func(t *testing.T) {
		require.Nil(t, s.GetOpenStores())
	})

	t.Run("close", func(t *testing.T) {
		require.NoError(t, s.Close())
	})
}
