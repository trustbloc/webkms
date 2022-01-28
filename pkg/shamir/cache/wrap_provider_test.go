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
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/kms/pkg/shamir/cache"
)

func TestWrappedProvider_Get(t *testing.T) {
	t.Run("Cache miss", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		c := NewMockCache(ctrl)

		var cachedValue interface{}

		c.EXPECT().Get(gomock.Any()).Return(nil, false).Times(1)

		c.EXPECT().SetWithTTL(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Do(func(key, value interface{}, cost int64, ttl time.Duration) {
				cachedValue = value
			}).Times(1)

		cacheProvider := cache.Provider{Cache: c}

		provider := NewMockShamirProvider(ctrl)

		provider.EXPECT().FetchSecretShare(gomock.Any()).Return([]byte("test shamir"), nil).Times(1)

		wp := cacheProvider.Wrap(provider, 10*time.Second)

		require.NotNil(t, wp)

		bytes, err := wp.FetchSecretShare("test_id")

		require.NoError(t, err)
		require.Equal(t, cachedValue, bytes)
	})

	t.Run("Cache hit", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		c := NewMockCache(ctrl)

		c.EXPECT().Get(gomock.Any()).Return([]byte("test shamir"), true).Times(1)
		c.EXPECT().SetWithTTL(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

		cacheProvider := cache.Provider{Cache: c}

		provider := NewMockShamirProvider(ctrl)

		provider.EXPECT().FetchSecretShare(gomock.Any()).Times(0)

		wp := cacheProvider.Wrap(provider, 10*time.Second)

		require.NotNil(t, wp)

		bytes, err := wp.FetchSecretShare("test_id")

		require.NoError(t, err)
		require.Equal(t, []byte("test shamir"), bytes)
	})

	t.Run("FetchSecretShare error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		c := NewMockCache(ctrl)

		c.EXPECT().Get(gomock.Any()).Return(nil, false).Times(1)

		c.EXPECT().SetWithTTL(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

		cacheProvider := cache.Provider{Cache: c}

		provider := NewMockShamirProvider(ctrl)

		provider.EXPECT().FetchSecretShare(gomock.Any()).Return(nil, errors.New("fetch error")).Times(1)

		wp := cacheProvider.Wrap(provider, 10*time.Second)

		require.NotNil(t, wp)

		bytes, err := wp.FetchSecretShare("test_id")

		require.EqualError(t, err, "fetch error")
		require.Nil(t, bytes)
	})
}
