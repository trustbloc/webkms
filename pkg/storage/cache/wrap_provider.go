/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cache

//go:generate mockgen -destination gomocks_test.go -package cache_test . Cache,StorageProvider,Store

import (
	"fmt"
	"sync"
	"time"

	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	cacheKeyFormat = "%s_%s"
	cacheItemCost  = 1
)

// Cache represents caching functionality. Concrete implementation is expected to be thread-safe.
type Cache interface {
	Get(key interface{}) (interface{}, bool)
	SetWithTTL(key, value interface{}, cost int64, ttl time.Duration) bool
	Del(key interface{})
	Clear()
}

// StorageProvider is an alias for storage.Provider.
type StorageProvider = storage.Provider

// Store is an alias for storage.Store.
type Store = storage.Store

// Provider provides the underlying StorageProvider with caching support.
type Provider struct {
	Cache Cache
}

type wrappedProvider struct {
	provider StorageProvider
	cache    Cache
	ttl      time.Duration
	stores   []Store
	mu       sync.Mutex
}

// Wrap adds caching support to the underlying StorageProvider.
func (p *Provider) Wrap(storageProvider StorageProvider, opts ...WrapOption) storage.Provider {
	o := &wrapOptions{
		cacheTTL: 0 * time.Second, // a zero value TTL means that items in the cache will never expire
	}

	for _, fn := range opts {
		fn(o)
	}

	return &wrappedProvider{
		provider: storageProvider,
		cache:    p.Cache,
		ttl:      o.cacheTTL,
	}
}

type wrapOptions struct {
	cacheTTL time.Duration
}

// WrapOption configures wrapped provider.
type WrapOption func(p *wrapOptions)

// WithCacheTTL sets the TTL (time to live) for cache items.
func WithCacheTTL(ttl time.Duration) WrapOption {
	return func(o *wrapOptions) {
		o.cacheTTL = ttl
	}
}

// OpenStore opens a Store that supports caching.
func (p *wrappedProvider) OpenStore(name string) (Store, error) {
	store, err := p.provider.OpenStore(name)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}

	ws := &wrappedStore{
		store:      store,
		namespace:  name,
		cache:      p.cache,
		ttl:        p.ttl,
		cachedKeys: make([]string, 0),
	}

	p.mu.Lock()
	p.stores = append(p.stores, ws)
	p.mu.Unlock()

	return ws, nil
}

// SetStoreConfig sets the configuration on the underlying Store.
func (p *wrappedProvider) SetStoreConfig(name string, config storage.StoreConfiguration) error {
	return p.provider.SetStoreConfig(name, config)
}

// GetStoreConfig gets the underlying Store configuration.
func (p *wrappedProvider) GetStoreConfig(name string) (storage.StoreConfiguration, error) {
	return p.provider.GetStoreConfig(name)
}

// GetOpenStores returns all Stores that are currently open in the underlying provider.
func (p *wrappedProvider) GetOpenStores() []Store {
	return p.provider.GetOpenStores()
}

// Close cleanups the cache and closes the underlying provider.
func (p *wrappedProvider) Close() error {
	for _, s := range p.stores {
		if err := s.Close(); err != nil {
			return fmt.Errorf("close store: %w", err)
		}
	}

	return p.provider.Close()
}

type wrappedStore struct {
	store      Store
	namespace  string
	cache      Cache
	ttl        time.Duration
	cachedKeys []string
	mu         sync.Mutex
}

// Put stores the key/value pair in the underlying storage and adds value to the cache.
func (s *wrappedStore) Put(key string, value []byte, tags ...storage.Tag) error {
	err := s.store.Put(key, value, tags...)
	if err != nil {
		return err
	}

	s.addToCache(key, value)

	return nil
}

// Get gets the value associated with the given key from the cache. If the value is not in the cache, it's fetched from
// the underlying storage and added to the cache.
func (s *wrappedStore) Get(key string) ([]byte, error) {
	v, ok := s.cache.Get(fmt.Sprintf(cacheKeyFormat, s.namespace, key))
	if ok {
		return v.([]byte), nil
	}

	b, err := s.store.Get(key)
	if err != nil {
		return nil, err
	}

	s.addToCache(key, b)

	return b, nil
}

// Close removes keys associated with the current store from the cache and closes the underlying storage.
func (s *wrappedStore) Close() error {
	for _, k := range s.cachedKeys {
		s.cache.Del(k)
	}

	return s.store.Close()
}

// GetTags fetches tags associated with the given key from the underlying storage.
func (s *wrappedStore) GetTags(key string) ([]storage.Tag, error) {
	return s.store.GetTags(key)
}

// GetBulk fetches the values associated with the given keys from the underlying storage. Cache is not used.
func (s *wrappedStore) GetBulk(keys ...string) ([][]byte, error) {
	return s.store.GetBulk(keys...)
}

// Query returns data from the underlying storage that satisfies the expression. Cache is not used.
func (s *wrappedStore) Query(expression string, options ...storage.QueryOption) (storage.Iterator, error) {
	return s.store.Query(expression, options...)
}

// Delete deletes the value from the underlying storage and cache.
func (s *wrappedStore) Delete(key string) error {
	if err := s.store.Delete(key); err != nil {
		return fmt.Errorf("delete key: %w", err)
	}

	s.cache.Del(fmt.Sprintf(cacheKeyFormat, s.namespace, key))

	return nil
}

// Batch performs multiple Put and/or Delete operations to the underlying storage. Values are not cached.
func (s *wrappedStore) Batch(operations []storage.Operation) error {
	return s.store.Batch(operations)
}

// Flush forces any queued up Put and/or Delete operations to the underlying storage to execute. Cache is not used.
func (s *wrappedStore) Flush() error {
	return s.store.Flush()
}

func (s *wrappedStore) addToCache(key string, value []byte) {
	k := fmt.Sprintf(cacheKeyFormat, s.namespace, key)

	s.cache.SetWithTTL(k, value, cacheItemCost, s.ttl)

	s.mu.Lock()
	s.cachedKeys = append(s.cachedKeys, k)
	s.mu.Unlock()
}
