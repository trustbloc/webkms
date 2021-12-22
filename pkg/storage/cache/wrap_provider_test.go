/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cache_test

import (
	"errors"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/kms/pkg/storage/cache"
)

func TestWrappedProvider_OpenStore(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		cacheProvider := cache.Provider{Cache: NewMockCache(ctrl)}

		p := NewMockStorageProvider(ctrl)
		p.EXPECT().OpenStore("test").Return(NewMockStore(ctrl), nil).Times(1)

		wp := cacheProvider.Wrap(p, cache.WithCacheTTL(10*time.Second))
		require.NotNil(t, wp)

		store, err := wp.OpenStore("test")
		require.NoError(t, err)
		require.NotNil(t, store)
	})

	t.Run("Fail to open store", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		cacheProvider := cache.Provider{Cache: NewMockCache(ctrl)}

		p := NewMockStorageProvider(ctrl)
		p.EXPECT().OpenStore("test").Return(nil, errors.New("open store error")).Times(1)

		wp := cacheProvider.Wrap(p)
		require.NotNil(t, wp)

		store, err := wp.OpenStore("test")
		require.EqualError(t, err, "open store: open store error")
		require.Nil(t, store)
	})
}

func TestWrappedProvider_SetStoreConfig(t *testing.T) {
	ctrl := gomock.NewController(t)

	cacheProvider := cache.Provider{Cache: NewMockCache(ctrl)}

	p := NewMockStorageProvider(ctrl)
	p.EXPECT().SetStoreConfig(gomock.Any(), gomock.Any()).Return(nil).Times(1)

	wp := cacheProvider.Wrap(p)
	require.NotNil(t, wp)

	err := wp.SetStoreConfig("test", storage.StoreConfiguration{})
	require.NoError(t, err)
}

func TestWrappedProvider_GetStoreConfig(t *testing.T) {
	ctrl := gomock.NewController(t)

	cacheProvider := cache.Provider{Cache: NewMockCache(ctrl)}

	p := NewMockStorageProvider(ctrl)
	p.EXPECT().GetStoreConfig(gomock.Any()).Return(storage.StoreConfiguration{}, nil)

	wp := cacheProvider.Wrap(p)
	require.NotNil(t, wp)

	c, err := wp.GetStoreConfig("test")
	require.NoError(t, err)
	require.NotNil(t, c)
}

func TestWrappedProvider_GetOpenStores(t *testing.T) {
	ctrl := gomock.NewController(t)

	cacheProvider := cache.Provider{Cache: NewMockCache(ctrl)}

	p := NewMockStorageProvider(ctrl)
	p.EXPECT().GetOpenStores().Return([]storage.Store{NewMockStore(ctrl)}).Times(1)

	wp := cacheProvider.Wrap(p)
	require.NotNil(t, wp)

	stores := wp.GetOpenStores()
	require.NotNil(t, stores)
	require.Equal(t, 1, len(stores))
}

func TestWrappedProvider_Close(t *testing.T) {
	ctrl := gomock.NewController(t)

	cacheProvider := cache.Provider{Cache: NewMockCache(ctrl)}

	p := NewMockStorageProvider(ctrl)
	p.EXPECT().Close().Return(nil).Times(1)

	wp := cacheProvider.Wrap(p)
	require.NotNil(t, wp)

	err := wp.Close()
	require.NoError(t, err)
}

func TestWrappedStore_Put(t *testing.T) {
	ctrl := gomock.NewController(t)

	c := NewMockCache(ctrl)
	c.EXPECT().SetWithTTL("test_key", []byte("test value"), int64(1), 0*time.Second).Times(1)

	cacheProvider := cache.Provider{Cache: c}

	s := NewMockStore(ctrl)
	s.EXPECT().Put("key", []byte("test value")).Return(nil).Times(1)

	p := NewMockStorageProvider(ctrl)
	p.EXPECT().OpenStore("test").Return(s, nil).Times(1)

	wp := cacheProvider.Wrap(p)
	require.NotNil(t, wp)

	store, err := wp.OpenStore("test")
	require.NoError(t, err)
	require.NotNil(t, store)

	err = store.Put("key", []byte("test value"))
	require.NoError(t, err)
}

func TestWrappedStore_Get(t *testing.T) {
	t.Run("Cache hit", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		c := NewMockCache(ctrl)
		c.EXPECT().Get("test_key").Return([]byte("test value"), true).Times(1)

		cacheProvider := cache.Provider{Cache: c}

		p := NewMockStorageProvider(ctrl)
		p.EXPECT().OpenStore("test").Return(NewMockStore(ctrl), nil).Times(1)

		wp := cacheProvider.Wrap(p)
		require.NotNil(t, wp)

		store, err := wp.OpenStore("test")
		require.NoError(t, err)
		require.NotNil(t, store)

		v, err := store.Get("key")
		require.NoError(t, err)
		require.Equal(t, []byte("test value"), v)
	})

	t.Run("Save to cache on miss", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		c := NewMockCache(ctrl)
		c.EXPECT().Get("test_key").Return(nil, false).Times(1)
		c.EXPECT().SetWithTTL("test_key", []byte("test value"), int64(1), 0*time.Second).Times(1)

		cacheProvider := cache.Provider{Cache: c}

		s := NewMockStore(ctrl)
		s.EXPECT().Get("key").Return([]byte("test value"), nil)

		p := NewMockStorageProvider(ctrl)
		p.EXPECT().OpenStore("test").Return(s, nil).Times(1)

		wp := cacheProvider.Wrap(p)
		require.NotNil(t, wp)

		store, err := wp.OpenStore("test")
		require.NoError(t, err)
		require.NotNil(t, store)

		v, err := store.Get("key")
		require.NoError(t, err)
		require.Equal(t, []byte("test value"), v)
	})
}

func TestWrappedStore_Close(t *testing.T) {
	ctrl := gomock.NewController(t)

	c := NewMockCache(ctrl)
	c.EXPECT().SetWithTTL("test_key", []byte("test value"), int64(1), 0*time.Second).Times(1)
	c.EXPECT().Del(gomock.Any()).Times(1)

	cacheProvider := cache.Provider{Cache: c}

	s := NewMockStore(ctrl)
	s.EXPECT().Put("key", []byte("test value")).Return(nil).Times(1)
	s.EXPECT().Close().Return(nil).Times(1)

	p := NewMockStorageProvider(ctrl)
	p.EXPECT().OpenStore("test").Return(s, nil).Times(1)

	wp := cacheProvider.Wrap(p)
	require.NotNil(t, wp)

	store, err := wp.OpenStore("test")
	require.NoError(t, err)
	require.NotNil(t, store)

	err = store.Put("key", []byte("test value"))
	require.NoError(t, err)

	err = store.Close()
	require.NoError(t, err)
}

func TestWrappedStore_GetTags(t *testing.T) {
	ctrl := gomock.NewController(t)

	cacheProvider := cache.Provider{Cache: NewMockCache(ctrl)}

	s := NewMockStore(ctrl)
	s.EXPECT().GetTags(gomock.Any()).Return([]storage.Tag{}, nil).Times(1)

	p := NewMockStorageProvider(ctrl)
	p.EXPECT().OpenStore("test").Return(s, nil).Times(1)

	wp := cacheProvider.Wrap(p)
	require.NotNil(t, wp)

	store, err := wp.OpenStore("test")
	require.NoError(t, err)
	require.NotNil(t, store)

	tags, err := store.GetTags("key")
	require.NoError(t, err)
	require.NotNil(t, tags)
}

func TestWrappedStore_GetBulk(t *testing.T) {
	ctrl := gomock.NewController(t)

	cacheProvider := cache.Provider{Cache: NewMockCache(ctrl)}

	s := NewMockStore(ctrl)
	s.EXPECT().GetBulk("key").Return([][]byte{}, nil)

	p := NewMockStorageProvider(ctrl)
	p.EXPECT().OpenStore("test").Return(s, nil).Times(1)

	wp := cacheProvider.Wrap(p)
	require.NotNil(t, wp)

	store, err := wp.OpenStore("test")
	require.NoError(t, err)
	require.NotNil(t, store)

	values, err := store.GetBulk("key")
	require.NoError(t, err)
	require.NotNil(t, values)
}

func TestWrappedStore_Query(t *testing.T) {
	ctrl := gomock.NewController(t)

	cacheProvider := cache.Provider{Cache: NewMockCache(ctrl)}

	s := NewMockStore(ctrl)
	s.EXPECT().Query("query expression").Return(nil, nil).Times(1)

	p := NewMockStorageProvider(ctrl)
	p.EXPECT().OpenStore("test").Return(s, nil).Times(1)

	wp := cacheProvider.Wrap(p)
	require.NotNil(t, wp)

	store, err := wp.OpenStore("test")
	require.NoError(t, err)
	require.NotNil(t, store)

	_, err = store.Query("query expression")
	require.NoError(t, err)
}

func TestWrappedStore_Delete(t *testing.T) {
	ctrl := gomock.NewController(t)

	c := NewMockCache(ctrl)
	c.EXPECT().Del("test_key").Times(1)

	cacheProvider := cache.Provider{Cache: c}

	s := NewMockStore(ctrl)
	s.EXPECT().Delete("key").Return(nil).Times(1)

	p := NewMockStorageProvider(ctrl)
	p.EXPECT().OpenStore("test").Return(s, nil).Times(1)

	wp := cacheProvider.Wrap(p)
	require.NotNil(t, wp)

	store, err := wp.OpenStore("test")
	require.NoError(t, err)
	require.NotNil(t, store)

	err = store.Delete("key")
	require.NoError(t, err)
}

func TestWrappedStore_Batch(t *testing.T) {
	ctrl := gomock.NewController(t)

	cacheProvider := cache.Provider{Cache: NewMockCache(ctrl)}

	s := NewMockStore(ctrl)
	s.EXPECT().Batch(gomock.Any()).Return(nil).Times(1)

	p := NewMockStorageProvider(ctrl)
	p.EXPECT().OpenStore("test").Return(s, nil).Times(1)

	wp := cacheProvider.Wrap(p)
	require.NotNil(t, wp)

	store, err := wp.OpenStore("test")
	require.NoError(t, err)
	require.NotNil(t, store)

	err = store.Batch(nil)
	require.NoError(t, err)
}

func TestWrappedStore_Flush(t *testing.T) {
	ctrl := gomock.NewController(t)

	cacheProvider := cache.Provider{Cache: NewMockCache(ctrl)}

	s := NewMockStore(ctrl)
	s.EXPECT().Flush().Return(nil).Times(1)

	p := NewMockStorageProvider(ctrl)
	p.EXPECT().OpenStore("test").Return(s, nil).Times(1)

	wp := cacheProvider.Wrap(p)
	require.NotNil(t, wp)

	store, err := wp.OpenStore("test")
	require.NoError(t, err)
	require.NotNil(t, store)

	err = store.Flush()
	require.NoError(t, err)
}
