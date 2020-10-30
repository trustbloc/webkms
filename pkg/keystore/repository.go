/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package keystore

import (
	"encoding/json"
	"errors"
	"sync"

	"github.com/trustbloc/edge-core/pkg/storage"
)

const (
	storeName = "keystoredb"
)

// Repository defines a persistence layer for the keystore.
type Repository interface {
	Get(id string) (*Keystore, error)
	Save(*Keystore) error
}

type repository struct {
	once            sync.Once
	storageProvider storage.Provider
	store           storage.Store
}

// NewRepository returns a new Repository instance backed by the specified storage.
func NewRepository(provider storage.Provider) Repository {
	return &repository{storageProvider: provider}
}

// Get retrieves the keystore by id.
func (r *repository) Get(id string) (*Keystore, error) {
	if err := r.initStore(); err != nil {
		return nil, err
	}

	bytes, err := r.store.Get(id)
	if err != nil {
		return nil, err
	}

	var k Keystore

	err = json.Unmarshal(bytes, &k)
	if err != nil {
		return nil, err
	}

	return &k, nil
}

// Save stores the keystore.
func (r *repository) Save(k *Keystore) error {
	if err := r.initStore(); err != nil {
		return err
	}

	bytes, err := json.Marshal(k)
	if err != nil {
		return err
	}

	err = r.store.Put(k.ID, bytes)
	if err != nil {
		return err
	}

	return nil
}

func (r *repository) initStore() error {
	var err error

	r.once.Do(func() {
		err = r.storageProvider.CreateStore(storeName)
		if errors.Is(err, storage.ErrDuplicateStore) {
			err = nil
		}

		r.store, err = r.storageProvider.OpenStore(storeName)
	})

	return err
}
