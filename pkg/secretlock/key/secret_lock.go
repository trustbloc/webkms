/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package key

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
)

type provider interface {
	KMS() kms.KeyManager
	Crypto() crypto.Crypto
}

// Lock is a secret lock based on private key.
type Lock struct {
	kms    kms.KeyManager
	crypto crypto.Crypto
}

// NewLock returns a new instance of key Lock.
func NewLock(p provider) *Lock {
	return &Lock{
		kms:    p.KMS(),
		crypto: p.Crypto(),
	}
}

// Encrypt encrypts request with key identified by keyURI.
func (l *Lock) Encrypt(keyURI string, req *secretlock.EncryptRequest) (*secretlock.EncryptResponse, error) {
	kh, err := l.kms.Get(keyURI)
	if err != nil {
		return nil, fmt.Errorf("get key handle: %w", err)
	}

	cipher, _, err := l.crypto.Encrypt([]byte(req.Plaintext), []byte(req.AdditionalAuthenticatedData), kh)
	if err != nil {
		return nil, fmt.Errorf("encrypt request: %w", err)
	}

	return &secretlock.EncryptResponse{
		Ciphertext: string(cipher),
	}, nil
}

// Decrypt decrypts request with key identified by keyURI.
func (l *Lock) Decrypt(keyURI string, req *secretlock.DecryptRequest) (*secretlock.DecryptResponse, error) {
	kh, err := l.kms.Get(keyURI)
	if err != nil {
		return nil, fmt.Errorf("get key handle: %w", err)
	}

	plain, err := l.crypto.Decrypt([]byte(req.Ciphertext), []byte(req.AdditionalAuthenticatedData), nil, kh)
	if err != nil {
		return nil, fmt.Errorf("decrypt request: %w", err)
	}

	return &secretlock.DecryptResponse{
		Plaintext: string(plain),
	}, nil
}
