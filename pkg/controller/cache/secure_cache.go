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

	"golang.org/x/crypto/bcrypt"
)

type cacheSecureItem struct {
	instance   interface{}
	bcryptHash []byte
	createdAt  time.Time
	mu         sync.Mutex
}

type createItemFunc = func() (interface{}, error)

// SecureCache is a cache that protected items with password.
type SecureCache interface {
	Get(id string, password []byte, createItem createItemFunc) (interface{}, error)
}

type secureCache struct {
	items           sync.Map
	cacheExpiration time.Duration
}

// NewSecureCache creates SecureCache instance.
func NewSecureCache(cacheExpiration time.Duration) SecureCache {
	return &secureCache{
		items:           sync.Map{},
		cacheExpiration: cacheExpiration,
	}
}

func (k *secureCache) Get(
	id string, password []byte, createItem createItemFunc) (interface{}, error) {
	if k.cacheExpiration == 0 {
		return createItem()
	}

	item, _ := k.items.LoadOrStore(id, &cacheSecureItem{})

	cacheItem, ok := item.(*cacheSecureItem)
	if !ok {
		return nil, errors.New("fail to cast item to cacheSecureItem type")
	}

	cacheItem.mu.Lock()
	defer cacheItem.mu.Unlock()

	now := time.Now()

	if cacheItem.instance != nil && now.Sub(cacheItem.createdAt) < k.cacheExpiration {
		err := bcrypt.CompareHashAndPassword(cacheItem.bcryptHash, password)
		if err == nil {
			return cacheItem.instance, nil
		}
	}

	bcryptHash, err := bcrypt.GenerateFromPassword(password, bcrypt.MinCost)
	if err != nil {
		return nil, fmt.Errorf("get bcrypt failed: %w", err)
	}

	instance, err := createItem()
	if err != nil {
		return nil, fmt.Errorf("createItem failed: %w", err)
	}

	cacheItem.instance = instance
	cacheItem.bcryptHash = bcryptHash
	cacheItem.createdAt = now

	return instance, nil
}
