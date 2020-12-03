/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cryptoutil

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/teserakt-io/golang-ed25519/extra25519"
)

const (
	defaultKeySize     = sha256.Size
	curve25519KeySize  = 32
	cryptoBoxNonceSize = 24
)

// GenerateKey generates a key of 32 bytes long.
func GenerateKey() []byte {
	return generateRandomBytes(defaultKeySize)
}

// GenerateNonceForCryptoBox generates nonce used by CryptoBox encryption.
func GenerateNonceForCryptoBox() []byte {
	return generateRandomBytes(cryptoBoxNonceSize)
}

// PublicEd25519toCurve25519 takes an Ed25519 public key and provides the corresponding Curve25519 public key.
func PublicEd25519toCurve25519(pub []byte) ([]byte, error) {
	if len(pub) == 0 {
		return nil, errors.New("public key is nil")
	}

	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%d-byte key size is invalid", len(pub))
	}

	pkOut := new([curve25519KeySize]byte)
	pKIn := new([curve25519KeySize]byte)
	copy(pKIn[:], pub)

	success := extra25519.PublicKeyToCurve25519(pkOut, pKIn)
	if !success {
		return nil, errors.New("error converting public key")
	}

	return pkOut[:], nil
}

// GenerateRandomBytes generates an array of n random bytes.
func generateRandomBytes(n uint32) []byte {
	buf := make([]byte, n)

	_, err := rand.Read(buf)
	if err != nil {
		panic(err)
	}

	return buf
}
