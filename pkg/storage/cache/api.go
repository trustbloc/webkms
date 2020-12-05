/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cache

import "time"

// Cache represents cache functionality.
type Cache interface {
	Get(key interface{}) (interface{}, error)
	SetWithExpire(key, value interface{}, expiration time.Duration) error
	Purge()
}
