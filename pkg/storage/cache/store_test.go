/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cache_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/log/mocklogger"

	mockcache "github.com/trustbloc/hub-kms/pkg/internal/mock/cache"
	"github.com/trustbloc/hub-kms/pkg/storage/cache"
)

func TestPut(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		s := &cache.Store{
			Cache:      &mockcache.MockCache{},
			Expiration: 0,
			Logger:     &mocklogger.MockLogger{},
		}

		err := s.Put("key", []byte("put value"))

		require.NoError(t, err)
	})

	t.Run("Error: set to cache", func(t *testing.T) {
		s := &cache.Store{
			Cache:      &mockcache.MockCache{SetWithExpireErr: errors.New("set error")},
			Expiration: 0,
			Logger:     &mocklogger.MockLogger{},
		}

		err := s.Put("key", []byte("put value"))

		require.Error(t, err)
		require.Equal(t, "set to cache: set error", err.Error())
	})
}

func TestGet(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		s := &cache.Store{
			Cache:      &mockcache.MockCache{GetValue: []byte("get value")},
			Expiration: 0,
			Logger:     &mocklogger.MockLogger{},
		}

		v, err := s.Get("key")

		require.NotNil(t, v)
		require.NoError(t, err)
	})

	t.Run("Error: set to cache", func(t *testing.T) {
		s := &cache.Store{
			Cache:      &mockcache.MockCache{GetErr: errors.New("get error")},
			Expiration: 0,
			Logger:     &mocklogger.MockLogger{},
		}

		v, err := s.Get("key")

		require.Nil(t, v)
		require.Error(t, err)
		require.Equal(t, "get from cache: get error", err.Error())
	})
}
