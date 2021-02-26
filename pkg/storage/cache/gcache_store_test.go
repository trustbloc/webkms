/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cache_test

import (
	"errors"
	"testing"
	"time"

	"github.com/bluele/gcache"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/log/mocklogger"

	"github.com/trustbloc/kms/pkg/storage/cache"
)

const (
	testStore = "store"
)

func TestNewProvider(t *testing.T) {
	p := cache.NewProvider()
	require.NotNil(t, p)
}

func TestProviderOpenStore(t *testing.T) {
	t.Run("create a new cache store", func(t *testing.T) {
		logger := &mocklogger.MockLogger{}
		p := cache.NewProvider(cache.WithLogger(logger))

		s, err := p.OpenStore(testStore)

		require.NotNil(t, s)
		require.NoError(t, err)
		require.Contains(t, logger.DebugLogContents, `new cache "store" created`)
	})

	t.Run("open previously created cache store", func(t *testing.T) {
		p := cache.NewProvider()

		_, err := p.OpenStore(testStore) // creates a new cache store
		require.NoError(t, err)

		s, err := p.OpenStore(testStore)

		require.NotNil(t, s)
		require.NoError(t, err)
	})
}

func TestProviderSetStoreConfig(t *testing.T) {
	p := cache.NewProvider()

	err := p.SetStoreConfig("", storage.StoreConfiguration{})

	require.EqualError(t, err, "not implemented")
}

func TestProviderGetStoreConfig(t *testing.T) {
	p := cache.NewProvider()

	config, err := p.GetStoreConfig("")

	require.EqualError(t, err, "not implemented")
	require.Empty(t, config)
}

func TestProviderGetOpenStores(t *testing.T) {
	p := cache.NewProvider()

	require.Panics(t, func() {
		p.GetOpenStores()
	})
}

func TestProviderClose(t *testing.T) {
	t.Run("purge cache for each namespace", func(t *testing.T) {
		cacheList := make([]*mockGCache, 2)

		i := 0
		p := cache.NewProvider(cache.WithGCacheCreator(func() cache.GCache {
			gc := &mockGCache{}
			cacheList[i] = gc
			i++

			return gc
		}))

		_, err := p.OpenStore(testStore)
		require.NoError(t, err)

		_, err = p.OpenStore("another store")
		require.NoError(t, err)

		err = p.Close()

		require.NoError(t, err)
		require.Equal(t, 2, len(cacheList)) // each namespace has its own cache store
		require.Equal(t, 1, cacheList[0].PurgeCalledTimes)
		require.Equal(t, 1, cacheList[1].PurgeCalledTimes)
	})
}

func TestStorePut(t *testing.T) {
	t.Run("put value into the cache", func(t *testing.T) {
		gc := gcache.New(0).Build()

		p := cache.NewProvider(cache.WithGCacheCreator(func() cache.GCache {
			return gc
		}))

		store, err := p.OpenStore(testStore)
		require.NotNil(t, store)
		require.NoError(t, err)

		err = store.Put("key", []byte("value"))

		require.NoError(t, err)
		require.True(t, gc.Has("key"))
	})

	t.Run("set returns an error", func(t *testing.T) {
		p := cache.NewProvider(cache.WithGCacheCreator(func() cache.GCache {
			return &mockGCache{SetWithExpireErr: errors.New("set error")}
		}))

		store, err := p.OpenStore(testStore)
		require.NotNil(t, store)
		require.NoError(t, err)

		err = store.Put("key", []byte("value"))

		require.Error(t, err)
		require.Equal(t, "set to cache: set error", err.Error())
	})

	t.Run("attempt to put tags in cache (not implemented)", func(t *testing.T) {
		gc := gcache.New(0).Build()

		p := cache.NewProvider(cache.WithGCacheCreator(func() cache.GCache {
			return gc
		}))

		store, err := p.OpenStore(testStore)
		require.NotNil(t, store)
		require.NoError(t, err)

		err = store.Put("key", []byte("value"), storage.Tag{
			Name:  "TagName",
			Value: "TagValue",
		})

		require.EqualError(t, err, "tag storage not implemented")
		require.True(t, !gc.Has("key"))
	})
}

func TestStoreGet(t *testing.T) {
	t.Run("retrieve value from the cache", func(t *testing.T) {
		gc := gcache.New(0).Build()
		err := gc.Set("key", []byte("value"))
		require.NoError(t, err)

		p := cache.NewProvider(cache.WithGCacheCreator(func() cache.GCache {
			return gc
		}))

		store, err := p.OpenStore(testStore)
		require.NotNil(t, store)
		require.NoError(t, err)

		v, err := store.Get("key")

		require.NoError(t, err)
		require.NotNil(t, v)
		require.Equal(t, []byte("value"), v)
	})

	t.Run("storage.ErrDataNotFound if key not found in the cache", func(t *testing.T) {
		p := cache.NewProvider()

		store, err := p.OpenStore(testStore)
		require.NotNil(t, store)
		require.NoError(t, err)

		v, err := store.Get("key")

		require.Nil(t, v)
		require.Error(t, err)
		require.Equal(t, storage.ErrDataNotFound, err)
	})

	t.Run("other than KeyNotFound error", func(t *testing.T) {
		p := cache.NewProvider(cache.WithGCacheCreator(func() cache.GCache {
			return &mockGCache{GetErr: errors.New("get error")}
		}))

		store, err := p.OpenStore(testStore)
		require.NotNil(t, store)
		require.NoError(t, err)

		v, err := store.Get("key")

		require.Nil(t, v)
		require.Error(t, err)
		require.Equal(t, "get from cache: get error", err.Error())
	})

	t.Run("no key in the cache after expiration", func(t *testing.T) {
		clock := gcache.NewFakeClock()
		exp := time.Minute

		gc := gcache.New(0).Clock(clock).Build()
		err := gc.SetWithExpire("key", []byte("value"), exp)
		require.NoError(t, err)

		p := cache.NewProvider(
			cache.WithGCacheCreator(func() cache.GCache {
				return gc
			}),
			cache.WithExpiration(exp),
		)

		store, err := p.OpenStore(testStore)
		require.NotNil(t, store)
		require.NoError(t, err)

		v, err := store.Get("key")

		require.NoError(t, err)
		require.NotNil(t, v)
		require.Equal(t, []byte("value"), v)

		clock.Advance(exp + time.Second)

		v, err = store.Get("key")
		require.Nil(t, v)
		require.Error(t, err)
		require.Equal(t, storage.ErrDataNotFound, err)
	})
}

func TestStoreGetTags(t *testing.T) {
	p := cache.NewProvider()

	store, err := p.OpenStore("store")

	require.NoError(t, err)

	tags, err := store.GetTags("key")

	require.EqualError(t, err, "not implemented")
	require.Nil(t, tags)
}

func TestStoreGetBulk(t *testing.T) {
	p := cache.NewProvider()

	store, err := p.OpenStore("store")

	require.NoError(t, err)

	values, err := store.GetBulk("key")

	require.EqualError(t, err, "not implemented")
	require.Nil(t, values)
}

func TestStoreQuery(t *testing.T) {
	p := cache.NewProvider()

	store, err := p.OpenStore("store")

	require.NoError(t, err)

	iterator, err := store.Query("expression")

	require.EqualError(t, err, "not implemented")
	require.Nil(t, iterator)
}

func TestStoreDelete(t *testing.T) {
	t.Run("remove item that exists in the cache", func(t *testing.T) {
		gc := gcache.New(0).Build()
		err := gc.Set("key", []byte("value"))
		require.NoError(t, err)

		p := cache.NewProvider(cache.WithGCacheCreator(func() cache.GCache {
			return gc
		}))

		store, err := p.OpenStore(testStore)
		require.NotNil(t, store)
		require.NoError(t, err)

		err = store.Delete("key")

		require.NoError(t, err)
		require.False(t, gc.Has("key"))
	})

	t.Run("remove item that is not in the cache", func(t *testing.T) {
		gc := gcache.New(0).Build()
		p := cache.NewProvider(cache.WithGCacheCreator(func() cache.GCache {
			return gc
		}))

		store, err := p.OpenStore(testStore)
		require.NotNil(t, store)
		require.NoError(t, err)

		err = store.Delete("key")

		require.NoError(t, err)
		require.False(t, gc.Has("key"))
	})
}

func TestStoreBatch(t *testing.T) {
	p := cache.NewProvider()

	store, err := p.OpenStore("store")

	require.NoError(t, err)

	err = store.Batch(nil)

	require.EqualError(t, err, "not implemented")
}

func TestStoreFlush(t *testing.T) {
	p := cache.NewProvider()

	store, err := p.OpenStore("store")

	require.NoError(t, err)

	err = store.Flush()

	require.EqualError(t, err, "not implemented")
}

func TestStoreClose(t *testing.T) {
	t.Run("purge cache upon closing", func(t *testing.T) {
		gc := &mockGCache{}
		p := cache.NewProvider(cache.WithGCacheCreator(func() cache.GCache {
			return gc
		}))

		store, err := p.OpenStore(testStore) // creates a new cache store
		require.NoError(t, err)

		err = store.Close()

		require.NoError(t, err)
		require.Equal(t, 1, gc.PurgeCalledTimes)
	})
}

type mockGCache struct {
	GetErr           error
	SetWithExpireErr error
	RemoveValue      bool
	PurgeCalledTimes int
}

func (m *mockGCache) Get(key interface{}) (interface{}, error) {
	return nil, m.GetErr
}

func (m *mockGCache) SetWithExpire(key, value interface{}, expiration time.Duration) error {
	return m.SetWithExpireErr
}

func (m *mockGCache) Remove(key interface{}) bool {
	return m.RemoveValue
}

func (m *mockGCache) Purge() {
	m.PurgeCalledTimes++
}
