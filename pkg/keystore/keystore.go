/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package keystore

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage/mem"
)

const localKeyURIPrefix = "local-lock://"

// Keystore represents a keystore.
type Keystore interface {
	CreateKey(kt kms.KeyType) (string, error)
	ExportKey(keyID string) ([]byte, error)
	CreateAndExportKey(kt kms.KeyType) (string, []byte, error)
	GetKeyHandle(keyID string) (interface{}, error)
	KeyManager() kms.KeyManager
}

type keystore struct {
	keyManager kms.KeyManager
}

// New returns a new Keystore instance.
func New(opts ...Option) (Keystore, error) {
	o := &Options{
		primaryKeyURI:   localKeyURIPrefix + "primaryKey",
		storageProvider: mem.NewProvider(),
		secretLock:      &noop.NoLock{},
	}

	for i := range opts {
		opts[i](o)
	}

	if o.kmsCreator == nil {
		o.kmsCreator = func(p kms.Provider) (kms.KeyManager, error) {
			return localkms.New(o.primaryKeyURI, p)
		}
	}

	p := kmsProvider{
		storageProvider: o.storageProvider,
		secretLock:      o.secretLock,
	}

	keyManager, err := o.kmsCreator(p)
	if err != nil {
		return nil, fmt.Errorf("new keystore: %w", err)
	}

	return &keystore{keyManager: keyManager}, nil
}

// CreateKey creates a new key.
func (k *keystore) CreateKey(kt kms.KeyType) (string, error) {
	keyID, _, err := k.keyManager.Create(kt)
	if err != nil {
		return "", fmt.Errorf("create key: %w", err)
	}

	return keyID, nil
}

// ExportKey exports a public key.
func (k *keystore) ExportKey(keyID string) ([]byte, error) {
	b, err := k.keyManager.ExportPubKeyBytes(keyID)
	if err != nil {
		return nil, fmt.Errorf("export key: %w", err)
	}

	return b, nil
}

// CreateAndExportKey creates a new key and exports its public part.
func (k *keystore) CreateAndExportKey(kt kms.KeyType) (string, []byte, error) {
	keyID, b, err := k.keyManager.CreateAndExportPubKeyBytes(kt)
	if err != nil {
		return "", nil, fmt.Errorf("create and export key: %w", err)
	}

	return keyID, b, nil
}

// GetKeyHandle retrieves key handle by keyID.
func (k *keystore) GetKeyHandle(keyID string) (interface{}, error) {
	kh, err := k.keyManager.Get(keyID)
	if err != nil {
		return nil, fmt.Errorf("get key handle: %w", err)
	}

	return kh, nil
}

// KeyManager returns KeyManager instance.
func (k *keystore) KeyManager() kms.KeyManager {
	return k.keyManager
}

// Options configures Keystore during creation.
type Options struct {
	primaryKeyURI   string
	storageProvider storage.Provider
	secretLock      secretlock.Service
	kmsCreator      kms.Creator
}

// Option configures Options.
type Option func(options *Options)

// WithPrimaryKeyURI sets the primary key URI.
func WithPrimaryKeyURI(uri string) Option {
	return func(o *Options) {
		o.primaryKeyURI = uri
	}
}

// WithStorageProvider sets the storage provider.
func WithStorageProvider(storageProvider storage.Provider) Option {
	return func(o *Options) {
		o.storageProvider = storageProvider
	}
}

// WithSecretLock sets the secret lock service.
func WithSecretLock(secretLock secretlock.Service) Option {
	return func(o *Options) {
		o.secretLock = secretLock
	}
}

// WithKMSCreator sets the KMS creator.
func WithKMSCreator(creator kms.Creator) Option {
	return func(o *Options) {
		o.kmsCreator = creator
	}
}

type kmsProvider struct {
	storageProvider storage.Provider
	secretLock      secretlock.Service
}

func (k kmsProvider) StorageProvider() storage.Provider {
	return k.storageProvider
}

func (k kmsProvider) SecretLock() secretlock.Service {
	return k.secretLock
}
