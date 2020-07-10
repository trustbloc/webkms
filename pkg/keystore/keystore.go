/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package keystore

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/trustbloc/edge-core/pkg/storage"
)

const (
	keystoreIDFormat = "urn:uuid:%s"
	configStoreKey   = "configuration"

	createStoreErr = "create store: %w"
	openStoreErr   = "open store: %w"
	storePutErr    = "store put: %w"

	marshalConfigErr  = "marshal configuration: %w"
	validateConfigErr = "validate configuration: %w"

	createKeyErr = "create key: %w"
)

var (
	// ErrDuplicateKeystore is returned when an attempt is made to create a duplicate keystore.
	ErrDuplicateKeystore = errors.New("duplicate keystore")
	// ErrMissingController is returned when no controller is specified in keystore configuration.
	ErrMissingController = errors.New("missing controller")
	// ErrInvalidStartingSequence is returned when keystore configuration has an invalid starting sequence.
	ErrInvalidStartingSequence = errors.New("invalid starting sequence")
	// ErrInvalidKeystore is returned when specified keystore can't be opened.
	ErrInvalidKeystore = errors.New("invalid keystore")
)

// Keystore represents a vault for keys with ability to call kms/crypto functions on them.
type Keystore struct {
	store  storage.Store
	kms    kms.KeyManager
	crypto crypto.Crypto
}

// New returns a new instance of keystore.
func New(keystoreID string, provider Provider) (*Keystore, error) {
	store, err := provider.StorageProvider().OpenStore(keystoreID)
	if err != nil {
		return nil, fmt.Errorf(openStoreErr, ErrInvalidKeystore)
	}

	return &Keystore{
		store:  store,
		kms:    provider.KMS(),
		crypto: provider.Crypto(),
	}, nil
}

// CreateKeystore creates a new keystore with provided configuration.
func CreateKeystore(config Configuration, storageProvider storage.Provider) (string, error) {
	err := validateConfig(config)
	if err != nil {
		return "", fmt.Errorf(validateConfigErr, err)
	}

	kID := keystoreID()
	err = storageProvider.CreateStore(kID)

	if errors.Is(err, storage.ErrDuplicateStore) {
		return "", fmt.Errorf(createStoreErr, ErrDuplicateKeystore)
	}

	if err != nil {
		return "", fmt.Errorf(createStoreErr, err)
	}

	store, err := storageProvider.OpenStore(kID)
	if err != nil {
		return "", fmt.Errorf(openStoreErr, err)
	}

	b, err := json.Marshal(config)
	if err != nil {
		return "", fmt.Errorf(marshalConfigErr, err)
	}

	err = store.Put(configStoreKey, b)
	if err != nil {
		return "", fmt.Errorf(storePutErr, err)
	}

	return kID, nil
}

// CreateKey generates a new key and associates it with the keystore.
func (k *Keystore) CreateKey(kt kms.KeyType) (string, error) {
	keyID, _, err := k.kms.Create(kt)
	if err != nil {
		return "", fmt.Errorf(createKeyErr, err)
	}

	err = k.store.Put(keyID, nil)
	if err != nil {
		return "", fmt.Errorf(storePutErr, err)
	}

	return keyID, nil
}

func validateConfig(config Configuration) error {
	if config.Controller == "" {
		return ErrMissingController
	}

	if config.Sequence != 0 {
		return ErrInvalidStartingSequence
	}

	return nil
}

func keystoreID() string {
	guid := uuid.New()
	return fmt.Sprintf(keystoreIDFormat, guid)
}
