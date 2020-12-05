/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gcache_test

import (
	"testing"
	"time"

	gcache2 "github.com/bluele/gcache"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/hub-kms/pkg/storage/cache/gcache"
)

const (
	testStore = "store"
)

func TestNewProvider(t *testing.T) {
	p := gcache.NewProvider()

	require.NotNil(t, p)
}

func TestOpenStore(t *testing.T) {
	t.Run("Add a new cache store", func(t *testing.T) {
		p := gcache.NewProvider()

		s, err := p.OpenStore(testStore)
		require.NotNil(t, s)
		require.NoError(t, err)
	})

	t.Run("Open previously added cache store", func(t *testing.T) {
		p := gcache.NewProvider()

		_, err := p.OpenStore(testStore)
		require.NoError(t, err)

		s, err := p.OpenStore(testStore)
		require.NotNil(t, s)
		require.NoError(t, err)
	})
}

func TestCloseStore(t *testing.T) {
	t.Run("Close cache store not in the cache list", func(t *testing.T) {
		p := gcache.NewProvider()

		err := p.CloseStore(testStore)
		require.NoError(t, err)
	})

	t.Run("Close cache store in the cache list", func(t *testing.T) {
		p := gcache.NewProvider()

		_, err := p.OpenStore(testStore)
		require.NoError(t, err)

		err = p.CloseStore(testStore)
		require.NoError(t, err)
	})
}

func TestClose(t *testing.T) {
	p := gcache.NewProvider()

	_, err := p.OpenStore(testStore)
	require.NoError(t, err)

	_, err = p.OpenStore("another store")
	require.NoError(t, err)

	err = p.Close()
	require.NoError(t, err)
}

func TestExpiration(t *testing.T) {
	clock := gcache2.NewFakeClock()
	exp := time.Minute

	p := gcache.NewProvider(
		gcache.WithClock(clock),
		gcache.WithExpiration(exp),
	)

	cache, err := p.OpenStore(testStore)
	require.NotNil(t, cache)
	require.NoError(t, err)

	err = cache.Put("key", []byte("value"))
	require.NoError(t, err)

	// should still be in the cache
	v, err := cache.Get("key")
	require.NotNil(t, v)
	require.NoError(t, err)

	clock.Advance(exp + time.Second)

	// should NOT be in the cache as time expires
	v, err = cache.Get("key")
	require.Nil(t, v)
	require.Error(t, err)
}
