/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cache

import (
	"fmt"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/trustbloc/edge-core/pkg/log"
)

// Store is a store with cache support.
type Store struct {
	Cache      Cache
	Expiration time.Duration
	Logger     log.Logger
}

// Put stores value in the cache.
func (s *Store) Put(k string, v []byte) error {
	err := s.Cache.SetWithExpire(k, v, s.Expiration)
	if err != nil {
		return fmt.Errorf("set to cache: %w", err)
	}

	return nil
}

// Get fetches value from the cache.
func (s *Store) Get(k string) ([]byte, error) {
	v, err := s.Cache.Get(k)
	if err != nil {
		return nil, fmt.Errorf("get from cache: %w", err)
	}

	return v.([]byte), nil
}

// Iterator returns store iterator (not implemented).
func (s *Store) Iterator(startKey, endKey string) storage.StoreIterator {
	panic("implement me")
}

// Delete deletes entry in the cache (not implemented).
func (s *Store) Delete(k string) error {
	panic("implement me")
}
