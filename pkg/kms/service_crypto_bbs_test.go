/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms_test

import (
	"errors"
	"testing"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/keyset"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/bbs"
	mockcrypto "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/kms/pkg/kms"
)

func TestSignMulti(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		svc, err := kms.NewService(&kms.Config{
			StorageProvider: mockstorage.NewMockStoreProvider(),
			CryptoService:   &mockcrypto.Crypto{BBSSignValue: []byte("signature")},
		})
		require.NoError(t, err)

		sig, err := svc.SignMulti([][]byte{[]byte("message 1"), []byte("message 2")}, nil)

		require.NotNil(t, sig)
		require.NoError(t, err)
	})

	t.Run("Fail to sign messages", func(t *testing.T) {
		svc, err := kms.NewService(&kms.Config{
			StorageProvider: mockstorage.NewMockStoreProvider(),
			CryptoService:   &mockcrypto.Crypto{BBSSignErr: errors.New("sign error")},
		})
		require.NoError(t, err)

		sig, err := svc.SignMulti([][]byte{[]byte("message 1"), []byte("message 2")}, nil)

		require.Nil(t, sig)
		require.Error(t, err)
	})
}

func TestVerifyMulti(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		svc, err := kms.NewService(&kms.Config{
			StorageProvider: mockstorage.NewMockStoreProvider(),
			CryptoService:   &mockcrypto.Crypto{},
		})
		require.NoError(t, err)

		kh, err := keyset.NewHandle(bbs.BLS12381G2KeyTemplate())
		require.NoError(t, err)

		err = svc.VerifyMulti([][]byte{[]byte("message 1"), []byte("message 2")}, []byte("signature"), kh)

		require.NoError(t, err)
	})

	t.Run("Fail to get public key from kh", func(t *testing.T) {
		svc, err := kms.NewService(&kms.Config{
			StorageProvider: mockstorage.NewMockStoreProvider(),
			CryptoService:   &mockcrypto.Crypto{},
		})
		require.NoError(t, err)

		badKH, err := keyset.NewHandle(aead.KMSEnvelopeAEADKeyTemplate("badUrl", nil))
		require.NoError(t, err)

		err = svc.VerifyMulti([][]byte{[]byte("message 1"), []byte("message 2")}, []byte("signature"), badKH)

		require.Error(t, err)
	})

	t.Run("Fail to verify a signature", func(t *testing.T) {
		svc, err := kms.NewService(&kms.Config{
			StorageProvider: mockstorage.NewMockStoreProvider(),
			CryptoService:   &mockcrypto.Crypto{BBSVerifyErr: errors.New("verify error")},
		})
		require.NoError(t, err)

		kh, err := keyset.NewHandle(bbs.BLS12381G2KeyTemplate())
		require.NoError(t, err)

		err = svc.VerifyMulti([][]byte{[]byte("message 1"), []byte("message 2")}, []byte("signature"), kh)

		require.Error(t, err)
	})
}

func TestDeriveProof(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		svc, err := kms.NewService(&kms.Config{
			StorageProvider: mockstorage.NewMockStoreProvider(),
			CryptoService:   &mockcrypto.Crypto{DeriveProofValue: []byte("proof")},
		})
		require.NoError(t, err)

		kh, err := keyset.NewHandle(bbs.BLS12381G2KeyTemplate())
		require.NoError(t, err)

		proof, err := svc.DeriveProof([][]byte{[]byte("message 1"), []byte("message 2")}, []byte("bbsSignature"),
			[]byte("nonce"), []int{1}, kh)

		require.NotNil(t, proof)
		require.NoError(t, err)
	})

	t.Run("Fail to get public key from kh", func(t *testing.T) {
		svc, err := kms.NewService(&kms.Config{
			StorageProvider: mockstorage.NewMockStoreProvider(),
			CryptoService:   &mockcrypto.Crypto{},
		})
		require.NoError(t, err)

		badKH, err := keyset.NewHandle(aead.KMSEnvelopeAEADKeyTemplate("badUrl", nil))
		require.NoError(t, err)

		proof, err := svc.DeriveProof([][]byte{[]byte("message 1"), []byte("message 2")}, []byte("bbsSignature"),
			[]byte("nonce"), []int{1}, badKH)

		require.Nil(t, proof)
		require.Error(t, err)
	})

	t.Run("Fail to derive proof", func(t *testing.T) {
		svc, err := kms.NewService(&kms.Config{
			StorageProvider: mockstorage.NewMockStoreProvider(),
			CryptoService:   &mockcrypto.Crypto{DeriveProofError: errors.New("derive proof error")},
		})
		require.NoError(t, err)

		kh, err := keyset.NewHandle(bbs.BLS12381G2KeyTemplate())
		require.NoError(t, err)

		proof, err := svc.DeriveProof([][]byte{[]byte("message 1"), []byte("message 2")}, []byte("bbsSignature"),
			[]byte("nonce"), []int{1}, kh)

		require.Nil(t, proof)
		require.Error(t, err)
	})
}

func TestVerifyProof(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		svc, err := kms.NewService(&kms.Config{
			StorageProvider: mockstorage.NewMockStoreProvider(),
			CryptoService:   &mockcrypto.Crypto{},
		})
		require.NoError(t, err)

		kh, err := keyset.NewHandle(bbs.BLS12381G2KeyTemplate())
		require.NoError(t, err)

		err = svc.VerifyProof([][]byte{[]byte("message 1")}, []byte("proof"), []byte("nonce"), kh)

		require.NoError(t, err)
	})

	t.Run("Fail to get public key from kh", func(t *testing.T) {
		svc, err := kms.NewService(&kms.Config{
			StorageProvider: mockstorage.NewMockStoreProvider(),
			CryptoService:   &mockcrypto.Crypto{},
		})
		require.NoError(t, err)

		badKH, err := keyset.NewHandle(aead.KMSEnvelopeAEADKeyTemplate("badUrl", nil))
		require.NoError(t, err)

		err = svc.VerifyProof([][]byte{[]byte("message 1")}, []byte("proof"), []byte("nonce"), badKH)

		require.Error(t, err)
	})

	t.Run("Fail to verify proof", func(t *testing.T) {
		svc, err := kms.NewService(&kms.Config{
			StorageProvider: mockstorage.NewMockStoreProvider(),
			CryptoService:   &mockcrypto.Crypto{VerifyProofErr: errors.New("verify proof error")},
		})
		require.NoError(t, err)

		kh, err := keyset.NewHandle(bbs.BLS12381G2KeyTemplate())
		require.NoError(t, err)

		err = svc.VerifyProof([][]byte{[]byte("message 1")}, []byte("proof"), []byte("nonce"), kh)

		require.Error(t, err)
	})
}
