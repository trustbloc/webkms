/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cache_test

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/mock/secretlock"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/kms/pkg/controller/cache"
)

func TestSecureCache(t *testing.T) {
	t.Run("Error on create", func(t *testing.T) {
		slCache := cache.NewSecureCache(time.Second * 10)

		_, err := slCache.Get("user1", []byte("secret share1"), func() (interface{}, error) {
			return nil, errors.New("create error")
		})

		require.EqualError(t, err, "createItem failed: create error")
	})

	t.Run("Get twice same", func(t *testing.T) {
		ksCache := cache.NewSecureCache(time.Second * 10)

		ks1, err := ksCache.Get("user1", []byte("secret share1"), createMockSecretLock)
		require.NoError(t, err)

		ks2, err := ksCache.Get("user1", []byte("secret share1"), createMockSecretLock)
		require.NoError(t, err)

		require.Same(t, ks1, ks2)
	})

	t.Run("Get twice (wrong share)", func(t *testing.T) {
		ksCache := cache.NewSecureCache(time.Second * 10)

		ks1, err := ksCache.Get("user1", []byte("secret share1"), createMockSecretLock)
		require.NoError(t, err)

		ks2, err := ksCache.Get("user1", []byte("secret share2"), createMockSecretLock)
		require.NoError(t, err)

		require.NotSame(t, ks1, ks2)
	})

	t.Run("Get twice (diff users)", func(t *testing.T) {
		ksCache := cache.NewSecureCache(time.Second * 10)

		ks1, err := ksCache.Get("user1", []byte("secret share1"), createMockSecretLock)
		require.NoError(t, err)

		ks2, err := ksCache.Get("user2", []byte("secret share1"), createMockSecretLock)
		require.NoError(t, err)

		require.NotSame(t, ks1, ks2)
	})

	t.Run("Get twice (time out expired)", func(t *testing.T) {
		ksCache := cache.NewSecureCache(0)

		ks1, err := ksCache.Get("user1", []byte("secret share1"), createMockSecretLock)
		require.NoError(t, err)

		ks2, err := ksCache.Get("user1", []byte("secret share1"), createMockSecretLock)
		require.NoError(t, err)

		require.NotSame(t, ks1, ks2)
	})

	t.Run("Get in parallel", func(t *testing.T) {
		ksCache := cache.NewSecureCache(time.Hour * 100)

		const groupsNum = 10
		const itemsInGroupNum = 100

		getGoroutine := &getItemGoroutine{
			ksCache: ksCache,
			t:       t,
			ch:      make(chan interface{}, groupsNum*itemsInGroupNum),
			wg:      &sync.WaitGroup{},
		}

		for g := 0; g < groupsNum; g++ {
			for i := 0; i < itemsInGroupNum; i++ {
				getGoroutine.wg.Add(1)
				go getGoroutine.getItem(g)
			}
		}

		getGoroutine.wg.Wait()
		close(getGoroutine.ch)

		ksMap := make(map[interface{}]int)
		for ks := range getGoroutine.ch {
			ksMap[ks]++
		}

		require.Equal(t, groupsNum, len(ksMap))

		for _, v := range ksMap {
			require.Equal(t, itemsInGroupNum, v)
		}
	})
}

func createMockSecretLock() (interface{}, error) {
	return &secretlock.MockSecretLock{}, nil
}

type getItemGoroutine struct {
	ksCache cache.SecureCache
	t       *testing.T
	ch      chan interface{}
	wg      *sync.WaitGroup
}

func (g *getItemGoroutine) getItem(group int) {
	ks1, err := g.ksCache.Get(fmt.Sprintf("user%d", group), []byte("secret share1"), createMockSecretLock)
	require.NoError(g.t, err)

	g.ch <- ks1
	g.wg.Done()
}
