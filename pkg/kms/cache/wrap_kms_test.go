/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cache_test

import (
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	arieskms "github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/kms/pkg/kms/cache"
)

func TestWrappedKMS_Wrap(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		cacheProvider := cache.Provider{Cache: NewMockCache(ctrl)}

		kms := NewMockKeyManager(ctrl)

		wk, err := cacheProvider.WrapKMS(kms, 10*time.Second)
		require.NoError(t, err)
		require.NotNil(t, wk)
	})

	t.Run("Fail to wrap", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		cacheProvider := cache.Provider{Cache: NewMockCache(ctrl)}

		kms := NewMockKeyManager(ctrl)

		wk, err := cacheProvider.WrapKMS(kms, 0)

		require.EqualError(t, err, "cacheTTL cant be less or equal to zero")
		require.Nil(t, wk)
	})
}

func TestWrappedKMS_Create(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	c := NewMockCache(ctrl)

	var cachedKey string

	var cachedValue interface{}

	c.EXPECT().SetWithTTL(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Do(func(key, value interface{}, cost int64, ttl time.Duration) {
			var ok bool

			cachedKey, ok = key.(string)
			if !ok {
				t.Errorf("invalid key type: %v", key)
			}
			cachedValue = value
		})

	cacheProvider := cache.Provider{Cache: c}

	kms := NewMockKeyManager(ctrl)

	kms.EXPECT().Create(gomock.Any()).Return("test_id", "fake_kh", nil).AnyTimes()

	wk, err := cacheProvider.WrapKMS(kms, 10*time.Second)
	require.NoError(t, err)
	require.NotNil(t, wk)

	keyID, kh, err := wk.Create(arieskms.AES256GCM)

	require.NoError(t, err)
	require.Equal(t, "kms_key_"+keyID, cachedKey)
	require.Equal(t, cachedValue, kh)
}

func TestWrappedKMS_Get(t *testing.T) {
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

		kms := NewMockKeyManager(ctrl)

		kms.EXPECT().Get(gomock.Any()).Return("fake_kh", nil).Times(1)

		wk, err := cacheProvider.WrapKMS(kms, 10*time.Second)

		require.NoError(t, err)
		require.NotNil(t, wk)

		kh, err := wk.Get("test_id")

		require.NoError(t, err)
		require.Equal(t, cachedValue, kh)
	})

	t.Run("Cache hit", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		c := NewMockCache(ctrl)

		c.EXPECT().Get(gomock.Any()).Return("fake_kh", true).Times(1)
		c.EXPECT().SetWithTTL(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

		cacheProvider := cache.Provider{Cache: c}

		kms := NewMockKeyManager(ctrl)

		kms.EXPECT().Get(gomock.Any()).Times(0)

		wk, err := cacheProvider.WrapKMS(kms, 10*time.Second)

		require.NoError(t, err)
		require.NotNil(t, wk)

		kh, err := wk.Get("test_id")

		require.NoError(t, err)
		require.Equal(t, "fake_kh", kh)
	})
}

func TestWrappedKMS_ExportPubKeyBytes(t *testing.T) {
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

		kms := NewMockKeyManager(ctrl)

		kms.EXPECT().ExportPubKeyBytes(gomock.Any()).Return([]byte("fake_byte"), arieskms.ED25519Type, nil).Times(1)

		wk, err := cacheProvider.WrapKMS(kms, 10*time.Second)

		require.NoError(t, err)
		require.NotNil(t, wk)

		bytes, _, err := wk.ExportPubKeyBytes("test_id")

		require.NoError(t, err)
		require.Equal(t, cachedValue, bytes)
	})

	t.Run("Cache hit", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		c := NewMockCache(ctrl)

		c.EXPECT().Get(gomock.Any()).Return([]byte("fake_byte"), true).Times(1)
		c.EXPECT().SetWithTTL(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

		cacheProvider := cache.Provider{Cache: c}

		kms := NewMockKeyManager(ctrl)

		kms.EXPECT().Get(gomock.Any()).Times(0)

		wk, err := cacheProvider.WrapKMS(kms, 10*time.Second)

		require.NoError(t, err)
		require.NotNil(t, wk)

		bytes, _, err := wk.ExportPubKeyBytes("test_id")

		require.NoError(t, err)
		require.Equal(t, []byte("fake_byte"), bytes)
	})
}

func TestWrappedKMS_CreateAndExportPubKeyBytes(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	c := NewMockCache(ctrl)

	var cachedKey string

	var cachedValue interface{}

	c.EXPECT().SetWithTTL(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Do(func(key, value interface{}, cost int64, ttl time.Duration) {
			var ok bool

			cachedKey, ok = key.(string)
			if !ok {
				t.Errorf("invalid key type: %v", key)
			}
			cachedValue = value
		})

	cacheProvider := cache.Provider{Cache: c}

	kms := NewMockKeyManager(ctrl)

	kms.EXPECT().CreateAndExportPubKeyBytes(gomock.Any()).Return("test_id", []byte("fake_bytes"), nil).Times(1)

	wk, err := cacheProvider.WrapKMS(kms, 10*time.Second)
	require.NoError(t, err)
	require.NotNil(t, wk)

	keyID, bytes, err := wk.CreateAndExportPubKeyBytes(arieskms.ED25519)

	require.NoError(t, err)
	require.Equal(t, "kms_key_pub_bytes_"+keyID, cachedKey)
	require.Equal(t, cachedValue, bytes)
}

func TestWrappedKMS_Rotate(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	c := NewMockCache(ctrl)
	cacheProvider := cache.Provider{Cache: c}

	kms := NewMockKeyManager(ctrl)

	kms.EXPECT().Rotate(gomock.Any(), gomock.Any()).Times(1)

	wk, err := cacheProvider.WrapKMS(kms, 10*time.Second)

	require.NoError(t, err)
	require.NotNil(t, wk)

	_, _, err = wk.Rotate(arieskms.AES256GCM, "test_id")

	require.NoError(t, err)
}

func TestWrappedKMS_PubKeyBytesToHandle(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	c := NewMockCache(ctrl)
	cacheProvider := cache.Provider{Cache: c}

	kms := NewMockKeyManager(ctrl)

	kms.EXPECT().PubKeyBytesToHandle(gomock.Any(), gomock.Any()).Times(1)

	wk, err := cacheProvider.WrapKMS(kms, 10*time.Second)

	require.NoError(t, err)
	require.NotNil(t, wk)

	_, err = wk.PubKeyBytesToHandle([]byte("fake"), arieskms.AES256GCM)

	require.NoError(t, err)
}

func TestWrappedKMS_ImportKey(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	c := NewMockCache(ctrl)
	cacheProvider := cache.Provider{Cache: c}

	kms := NewMockKeyManager(ctrl)

	kms.EXPECT().ImportPrivateKey(gomock.Any(), gomock.Any()).Times(1)

	wk, err := cacheProvider.WrapKMS(kms, 10*time.Second)

	require.NoError(t, err)
	require.NotNil(t, wk)

	_, _, err = wk.ImportPrivateKey([]byte("fake"), arieskms.AES256GCM)

	require.NoError(t, err)
}
