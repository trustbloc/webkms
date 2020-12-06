/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cache

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/bluele/gcache"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/trustbloc/edge-core/pkg/log"
)

const (
	cacheExpMinutes = 10
)

// GCache represents GCache implementation.
type GCache interface {
	Get(key interface{}) (interface{}, error)
	SetWithExpire(key, value interface{}, expiration time.Duration) error
	Remove(key interface{}) bool
	Purge()
}

// Creator defines function to create a new GCache instance.
type Creator func() GCache

// Provider contains dependencies for a storage provider based on GCache.
type Provider struct {
	cacheList map[string]*cacheStore
	gcCreator Creator
	exp       time.Duration
	logger    log.Logger
	mu        sync.RWMutex
}

// NewProvider returns a new storage provider instance based on GCache.
func NewProvider(opts ...Option) *Provider {
	o := &Options{
		gcCreator: func() GCache { return gcache.New(0).Build() },
		exp:       cacheExpMinutes * time.Minute,
		logger:    log.New("hub-kms/cache"),
	}

	for i := range opts {
		opts[i](o)
	}

	return &Provider{
		cacheList: make(map[string]*cacheStore),
		gcCreator: o.gcCreator,
		exp:       o.exp,
		logger:    o.logger,
	}
}

// OpenStore opens and returns a new cache store for the given namespace.
func (p *Provider) OpenStore(name string) (storage.Store, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	s, ok := p.cacheList[name]
	if !ok {
		s = &cacheStore{
			name:   name,
			gc:     p.gcCreator(),
			exp:    p.exp,
			logger: p.logger,
		}

		p.cacheList[name] = s

		p.logger.Debugf("new cache %q created", name)

		return s, nil
	}

	return s, nil
}

// CloseStore purges cache store for the given namespace.
func (p *Provider) CloseStore(name string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	s, ok := p.cacheList[name]
	if !ok {
		return nil
	}

	s.gc.Purge()
	delete(p.cacheList, name)

	return nil
}

// Close purges all opened cache stores.
func (p *Provider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, s := range p.cacheList {
		s.gc.Purge()
	}

	p.cacheList = make(map[string]*cacheStore)

	return nil
}

// Options configures Provider dependencies.
type Options struct {
	gcCreator Creator
	exp       time.Duration
	logger    log.Logger
}

// Option configures Options.
type Option func(options *Options)

// WithGCacheCreator sets the function to create a new GCache instance.
func WithGCacheCreator(c Creator) Option {
	return func(o *Options) {
		o.gcCreator = c
	}
}

// WithExpiration sets the custom cache expiration duration.
func WithExpiration(d time.Duration) Option {
	return func(o *Options) {
		o.exp = d
	}
}

// WithLogger sets the custom logger.
func WithLogger(l log.Logger) Option {
	return func(o *Options) {
		o.logger = l
	}
}

// Store is a store backed by GCache.
type cacheStore struct {
	name   string
	gc     GCache
	exp    time.Duration
	logger log.Logger
}

// Get fetches value from the cache by key.
func (s *cacheStore) Get(k string) ([]byte, error) {
	v, err := s.gc.Get(k)
	if err != nil {
		if errors.Is(err, gcache.KeyNotFoundError) {
			s.logger.Debugf("no key %q in cache %q", k, s.name)

			return nil, storage.ErrDataNotFound
		}

		return nil, fmt.Errorf("get from cache: %w", err)
	}

	s.logger.Debugf("get key %q from cache %q", k, s.name)

	return v.([]byte), nil
}

// Put stores a new key-value pair with an expiration time set for the cacheStore instance.
func (s *cacheStore) Put(k string, v []byte) error {
	err := s.gc.SetWithExpire(k, v, s.exp)
	if err != nil {
		return fmt.Errorf("set to cache: %w", err)
	}

	s.logger.Debugf("save key %q into cache %q", k, s.name)

	return nil
}

// Delete removes key and associated value from the cache.
func (s *cacheStore) Delete(k string) error {
	if ok := s.gc.Remove(k); ok {
		s.logger.Debugf("delete key %q from cache %q", k, s.name)
	}

	return nil
}

// Iterator returns store iterator (not implemented).
func (s *cacheStore) Iterator(startKey, endKey string) storage.StoreIterator {
	panic("implement me")
}
