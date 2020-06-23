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
	"github.com/trustbloc/edge-core/pkg/storage"
)

const (
	keystoreIDFormat = "urn:uuid:%s"
	configStoreKey   = "config"

	checkConfigErr   = "check config: %w"
	createStoreErr   = "create store: %w"
	openStoreErr     = "open store: %w"
	marshalConfigErr = "marshal config: %w"
	storePutErr      = "store put: %w"
)

var (
	// ErrDuplicateKeystore is returned when an attempt is made to create a duplicate keystore.
	ErrDuplicateKeystore = errors.New("duplicate keystore")
	// ErrMissingController is returned when no controller is specified in keystore configuration.
	ErrMissingController = errors.New("missing controller")
	// ErrInvalidStartingSequence is returned when keystore configuration has an invalid starting sequence.
	ErrInvalidStartingSequence = errors.New("invalid starting sequence")
)

// Keystore represents a vault for storing keys.
type Keystore struct {
	provider storage.Provider
}

// Config represents a keystore configuration.
type Config struct {
	// Counter for the keystore configuration to ensure that clients are properly synchronized.
	Sequence int `json:"sequence"`
	// Entity that is in control of the keystore.
	Controller string `json:"controller"`
}

// New returns a new instance of keystore.
func New(provider storage.Provider) *Keystore {
	return &Keystore{provider: provider}
}

// Create creates a new keystore with provided configuration and returns its ID.
func (k *Keystore) Create(config Config) (string, error) {
	err := checkConfig(config)
	if err != nil {
		return "", fmt.Errorf(checkConfigErr, err)
	}

	kID := newKeystoreID()
	err = k.provider.CreateStore(kID)

	if errors.Is(err, storage.ErrDuplicateStore) {
		return "", fmt.Errorf(createStoreErr, ErrDuplicateKeystore)
	}

	if err != nil {
		return "", fmt.Errorf(createStoreErr, err)
	}

	store, err := k.provider.OpenStore(kID)
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

func checkConfig(config Config) error {
	if config.Controller == "" {
		return ErrMissingController
	}

	if config.Sequence != 0 {
		return ErrInvalidStartingSequence
	}

	return nil
}

func newKeystoreID() string {
	guid := uuid.New()
	return fmt.Sprintf(keystoreIDFormat, guid)
}
