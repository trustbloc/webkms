/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cache

//go:generate mockgen -destination gomocks_test.go -package cache_test . Cache,ShamirProvider

import (
	"fmt"
	"time"

	"github.com/trustbloc/kms/pkg/shamir"
)

const (
	keyNamespace   = "shamir_secret"
	cacheKeyFormat = "%s_%s"
	cacheItemCost  = 1
)

// Cache represents caching functionality. Concrete implementation is expected to be thread-safe,
// and clean up items when ttl is expired.
type Cache interface {
	Get(key interface{}) (interface{}, bool)
	SetWithTTL(key, value interface{}, cost int64, ttl time.Duration) bool
	Del(key interface{})
}

// Provider provides cache support for sensitive data like unencrypted keys from KeyManager, and Shamir secret shares.
type Provider struct {
	Cache Cache
}

// ShamirProvider is an alias for shamir.Provider.
type ShamirProvider = shamir.Provider

type wrappedProvider struct {
	provider ShamirProvider
	cache    Cache
	ttl      time.Duration
}

// Wrap adds caching support to the underlying ShamirProvider.
func (p *Provider) Wrap(provider ShamirProvider, cacheTTL time.Duration) ShamirProvider {
	return &wrappedProvider{
		provider: provider,
		cache:    p.Cache,
		ttl:      cacheTTL,
	}
}

func (p *wrappedProvider) FetchSecretShare(subject string) ([]byte, error) {
	secret, ok := p.cache.Get(keyCacheItemID(subject))
	if ok {
		return secret.([]byte), nil
	}

	secretBytes, err := p.provider.FetchSecretShare(subject)
	if err != nil {
		return nil, err
	}

	p.addSecretToCache(subject, secretBytes)

	return secretBytes, nil
}

func keyCacheItemID(subject string) string {
	return fmt.Sprintf(cacheKeyFormat, keyNamespace, subject)
}

func (p *wrappedProvider) addSecretToCache(subject string, secret []byte) {
	p.cache.SetWithTTL(keyCacheItemID(subject), secret, cacheItemCost, p.ttl)
}
