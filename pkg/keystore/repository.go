/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package keystore

import (
	"encoding/json"
	"errors"

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
	store storage.Store
}

// NewRepository returns a new Repository instance backed by the specified storage.
func NewRepository(provider storage.Provider) (Repository, error) {
	err := provider.CreateStore(storeName)
	if err != nil && !errors.Is(err,storage.ErrDuplicateStore) {
		return nil, err
	}

	store, err := provider.OpenStore(storeName)
	if err != nil {
		return nil, err
	}

	return &repository{store: store}, nil
}

// Get retrieves the keystore by id.
func (s *repository) Get(id string) (*Keystore, error) {
	bytes, err := s.store.Get(id)
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
func (s *repository) Save(k *Keystore) error {
	bytes, err := json.Marshal(k)
	if err != nil {
		return err
	}

	err = s.store.Put(k.ID, bytes)
	if err != nil {
		return err
	}

	return nil
}
