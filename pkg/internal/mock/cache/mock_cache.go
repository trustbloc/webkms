/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cache

import "time"

// MockCache is a mock cache.
type MockCache struct {
	GetValue         []byte
	GetErr           error
	SetWithExpireErr error
	PurgeWasCalled   bool
}

// Get gets value from the cache.
func (c *MockCache) Get(key interface{}) (interface{}, error) {
	if c.GetErr != nil {
		return nil, c.GetErr
	}

	return c.GetValue, nil
}

// SetWithExpire sets a new key-value pair with an expiration time.
func (c *MockCache) SetWithExpire(key, value interface{}, expiration time.Duration) error {
	if c.SetWithExpireErr != nil {
		return c.SetWithExpireErr
	}

	return nil
}

// Purge clears the cache.
func (c *MockCache) Purge() {
	c.PurgeWasCalled = true
}
