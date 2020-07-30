/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package keystore

import (
	"sync"

	"github.com/trustbloc/edge-core/pkg/storage"

	"github.com/trustbloc/hub-kms/pkg/keystore"
)

type MockRepository struct {
	Store   map[string]*keystore.Keystore
	lock    sync.RWMutex
	ErrGet  error
	ErrSave error
}

func NewMockRepository() *MockRepository {
	return &MockRepository{Store: map[string]*keystore.Keystore{}}
}

func (r *MockRepository) Get(id string) (*keystore.Keystore, error) {
	if r.ErrGet != nil {
		return nil, r.ErrGet
	}

	r.lock.RLock()
	defer r.lock.RUnlock()

	k, ok := r.Store[id]
	if !ok {
		return nil, storage.ErrValueNotFound
	}

	return k, nil
}

func (r *MockRepository) Save(k *keystore.Keystore) error {
	if r.ErrSave != nil {
		return r.ErrSave
	}

	r.lock.Lock()
	r.Store[k.ID] = k
	r.lock.Unlock()

	return nil
}
