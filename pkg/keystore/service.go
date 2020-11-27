/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package keystore

import (
	"encoding/json"
	"errors"
	"fmt"

	arieskms "github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/trustbloc/edge-core/pkg/storage"
)

const (
	storeName = "keystoredb"
)

// Service provides functionality for working with Keystore.
type Service interface {
	Create(options ...Option) (*Keystore, error)
	Get(keystoreID string) (*Keystore, error)
	Save(k *Keystore) error
	GetKeyHandle(keyID string) (interface{}, error)
	KeyManager() (arieskms.KeyManager, error)
}

// Provider contains dependencies for the Keystore service.
type Provider interface {
	StorageProvider() storage.Provider
	KeyManagerProvider() arieskms.Provider
	KeyManagerCreator() arieskms.Creator
}

type service struct {
	store      storage.Store
	keyManager arieskms.KeyManager
}

// NewService returns a new Service instance.
func NewService(provider Provider) (Service, error) {
	err := provider.StorageProvider().CreateStore(storeName)
	if err != nil && !errors.Is(err, storage.ErrDuplicateStore) {
		return nil, err
	}

	store, err := provider.StorageProvider().OpenStore(storeName)
	if err != nil {
		return nil, err
	}

	keyManager, err := provider.KeyManagerCreator()(provider.KeyManagerProvider())
	if err != nil {
		return nil, fmt.Errorf("failed to create keyManager: %w", err)
	}

	return &service{
		store:      store,
		keyManager: keyManager,
	}, nil
}

// Create creates a new Keystore.
func (s *service) Create(options ...Option) (*Keystore, error) {
	opts := &Options{}

	for i := range options {
		options[i](opts)
	}

	k := &Keystore{
		ID:         opts.ID,
		Controller: opts.Controller,
		VaultID:    opts.VaultID,
		CreatedAt:  opts.CreatedAt,
	}

	if opts.DelegateKeyType != "" {
		keyID, _, err := s.keyManager.Create(opts.DelegateKeyType)
		if err != nil {
			return nil, err
		}

		k.DelegateKeyID = keyID
	}

	if opts.RecipientKeyType != "" {
		keyID, _, err := s.keyManager.Create(opts.RecipientKeyType)
		if err != nil {
			return nil, err
		}

		k.RecipientKeyID = keyID
	}

	if opts.MACKeyType != "" {
		keyID, _, err := s.keyManager.Create(opts.MACKeyType)
		if err != nil {
			return nil, err
		}

		k.MACKeyID = keyID
	}

	bytes, err := json.Marshal(k)
	if err != nil {
		return nil, err
	}

	err = s.store.Put(k.ID, bytes)
	if err != nil {
		return nil, err
	}

	return k, nil
}

// Get retrieves Keystore by ID.
func (s *service) Get(keystoreID string) (*Keystore, error) {
	bytes, err := s.store.Get(keystoreID)
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

// Save stores Keystore.
func (s *service) Save(k *Keystore) error {
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

// GetKeyHandle retrieves key handle by keyID.
func (s *service) GetKeyHandle(keyID string) (interface{}, error) {
	kh, err := s.keyManager.Get(keyID)
	if err != nil {
		return nil, err
	}

	return kh, nil
}

// KeyManager returns KeyManager that the Keystore service was initialized with.
func (s *service) KeyManager() (arieskms.KeyManager, error) {
	return s.keyManager, nil
}
