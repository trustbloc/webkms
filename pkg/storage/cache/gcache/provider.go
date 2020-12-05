/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gcache

import (
	"sync"
	"time"

	"github.com/bluele/gcache"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/hub-kms/pkg/storage/cache"
)

const (
	cacheExpMinutes = 10
)

// Provider contains dependencies for the GCache storage provider.
type Provider struct {
	caches     map[string]*cache.Store
	expiration time.Duration
	logger     log.Logger
	clock      gcache.Clock
	mu         sync.RWMutex
}

// NewProvider returns a new storage provider instance backed by GCache.
func NewProvider(opts ...Option) *Provider {
	o := &Options{
		expiration: cacheExpMinutes * time.Minute,
		logger:     log.New("hub-kms/cache"),
		clock:      gcache.NewRealClock(),
	}

	for i := range opts {
		opts[i](o)
	}

	return &Provider{
		caches:     make(map[string]*cache.Store),
		expiration: o.expiration,
		logger:     o.logger,
		clock:      o.clock,
		mu:         sync.RWMutex{},
	}
}

// OpenStore opens and returns a new cache store for the given namespace.
func (p *Provider) OpenStore(name string) (storage.Store, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	c, ok := p.caches[name]
	if !ok {
		c = &cache.Store{
			Cache:      gcache.New(0).Clock(p.clock).Build(),
			Expiration: p.expiration,
			Logger:     p.logger,
		}

		p.caches[name] = c

		return c, nil
	}

	return c, nil
}

// CloseStore purges named cache store.
func (p *Provider) CloseStore(name string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	s, ok := p.caches[name]
	if !ok {
		return nil
	}

	s.Cache.Purge()
	delete(p.caches, name)

	return nil
}

// Close purges all opened cache stores.
func (p *Provider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, s := range p.caches {
		s.Cache.Purge()
	}

	p.caches = make(map[string]*cache.Store)

	return nil
}

// Options configures provider dependencies.
type Options struct {
	expiration time.Duration
	logger     log.Logger
	clock      gcache.Clock
}

// Option configures Options.
type Option func(options *Options)

// WithExpiration sets the custom cache expiration duration.
func WithExpiration(d time.Duration) Option {
	return func(o *Options) {
		o.expiration = d
	}
}

// WithClock sets the custom gcache clock.
func WithClock(c gcache.Clock) Option {
	return func(o *Options) {
		o.clock = c
	}
}
