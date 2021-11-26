/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package key

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
)

const nonceLenBytes = 4

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

	cipher, nonce, err := l.crypto.Encrypt([]byte(req.Plaintext), []byte(req.AdditionalAuthenticatedData), kh)
	if err != nil {
		return nil, fmt.Errorf("encrypt request: %w", err)
	}

	cipherWithNonce, err := buildCipherText(cipher, nonce)
	if err != nil {
		return nil, fmt.Errorf("encrypt request: %w", err)
	}

	return &secretlock.EncryptResponse{
		Ciphertext: base64.URLEncoding.EncodeToString(cipherWithNonce),
	}, nil
}

// Decrypt decrypts request with key identified by keyURI.
func (l *Lock) Decrypt(keyURI string, req *secretlock.DecryptRequest) (*secretlock.DecryptResponse, error) {
	kh, err := l.kms.Get(keyURI)
	if err != nil {
		return nil, fmt.Errorf("get key handle: %w", err)
	}

	cipher, err := base64.URLEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}

	if len(cipher) <= nonceLenBytes {
		return nil, errors.New("decrypt request: invalid ciphertext")
	}

	// Extract length of nonce and advance past that length.
	nonceLen := int(binary.BigEndian.Uint32(cipher[:nonceLenBytes]))
	cipher = cipher[nonceLenBytes:]

	// Verify we have enough bytes for the nonce.
	if nonceLen <= 0 || len(cipher) < nonceLen {
		return nil, errors.New("decrypt request: invalid ciphertext")
	}

	// Extract the encrypted DEK and the payload.
	nonce := cipher[:nonceLen]
	payload := cipher[nonceLen:]

	plain, err := l.crypto.Decrypt(payload, []byte(req.AdditionalAuthenticatedData), nonce, kh)
	if err != nil {
		return nil, fmt.Errorf("decrypt request: %w", err)
	}

	return &secretlock.DecryptResponse{
		Plaintext: string(plain),
	}, nil
}

// buildCipherText builds the cipher text by appending the nonce length, nonce
// and the encrypted payload.
func buildCipherText(payload, nonce []byte) ([]byte, error) {
	var b bytes.Buffer

	// Write the length of the nonce.
	nonceLenBuf := make([]byte, nonceLenBytes)
	binary.BigEndian.PutUint32(nonceLenBuf, uint32(len(nonce)))

	_, err := b.Write(nonceLenBuf)
	if err != nil {
		return nil, err
	}

	_, err = b.Write(nonce)
	if err != nil {
		return nil, err
	}

	_, err = b.Write(payload)
	if err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}
