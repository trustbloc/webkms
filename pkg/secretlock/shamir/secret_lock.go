/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package shamir

import (
	"crypto/sha256"
	"fmt"

	"github.com/hashicorp/vault/shamir"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/local/masterlock/hkdf"
)

// Lock is a secret lock based on shamir secret split.
type Lock struct {
	secret []byte
}

// NewLock returns a new instance of shamir Lock.
func NewLock(secretShares [][]byte) (*Lock, error) {
	combined, err := shamir.Combine(secretShares)
	if err != nil {
		return nil, fmt.Errorf("shamir combine: %w", err)
	}

	return &Lock{secret: combined}, nil
}

// Encrypt encrypts request with key identified by keyURI.
func (l *Lock) Encrypt(keyURI string, req *secretlock.EncryptRequest) (*secretlock.EncryptResponse, error) {
	secretLock, err := hkdf.NewMasterLock(string(l.secret), sha256.New, nil)
	if err != nil {
		return nil, fmt.Errorf("create hkdf lock: %w", err)
	}

	return secretLock.Encrypt(keyURI, req)
}

// Decrypt decrypts request with key identified by keyURI.
func (l *Lock) Decrypt(keyURI string, req *secretlock.DecryptRequest) (*secretlock.DecryptResponse, error) {
	secretLock, err := hkdf.NewMasterLock(string(l.secret), sha256.New, nil)
	if err != nil {
		return nil, fmt.Errorf("create hkdf lock: %w", err)
	}

	return secretLock.Decrypt(keyURI, req)
}
