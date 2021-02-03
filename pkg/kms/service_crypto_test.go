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
	"github.com/google/tink/go/signature"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	mockcrypto "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/kms/pkg/kms"
)

func TestSign(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		svc, err := kms.NewService(&kms.Config{
			StorageProvider: mockstorage.NewMockStoreProvider(),
			CryptoService:   &mockcrypto.Crypto{SignValue: []byte("signature")},
		})
		require.NoError(t, err)

		sig, err := svc.Sign([]byte("test message"), nil)

		require.NotNil(t, sig)
		require.NoError(t, err)
	})

	t.Run("Fail to sign a message", func(t *testing.T) {
		svc, err := kms.NewService(&kms.Config{
			StorageProvider: mockstorage.NewMockStoreProvider(),
			CryptoService:   &mockcrypto.Crypto{SignErr: errors.New("sign error")},
		})
		require.NoError(t, err)

		sig, err := svc.Sign([]byte("test message"), nil)

		require.Nil(t, sig)
		require.Error(t, err)
	})
}

func TestVerify(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		svc, err := kms.NewService(&kms.Config{
			StorageProvider: mockstorage.NewMockStoreProvider(),
			CryptoService:   &mockcrypto.Crypto{},
		})
		require.NoError(t, err)

		kh, err := keyset.NewHandle(signature.ED25519KeyTemplate())
		require.NoError(t, err)

		err = svc.Verify([]byte("signature"), []byte("test message"), kh)

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

		err = svc.Verify([]byte("signature"), []byte("test message"), badKH)

		require.Error(t, err)
	})

	t.Run("Fail to verify a signature", func(t *testing.T) {
		svc, err := kms.NewService(&kms.Config{
			StorageProvider: mockstorage.NewMockStoreProvider(),
			CryptoService:   &mockcrypto.Crypto{VerifyErr: errors.New("verify error")},
		})
		require.NoError(t, err)

		kh, err := keyset.NewHandle(signature.ED25519KeyTemplate())
		require.NoError(t, err)

		err = svc.Verify([]byte("signature"), []byte("test message"), kh)

		require.Error(t, err)
	})
}

func TestEncrypt(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		svc, err := kms.NewService(&kms.Config{
			StorageProvider: mockstorage.NewMockStoreProvider(),
			CryptoService: &mockcrypto.Crypto{
				EncryptValue:      []byte("cipher"),
				EncryptNonceValue: []byte("nonce"),
			},
		})
		require.NoError(t, err)

		cipher, nonce, err := svc.Encrypt([]byte("test message"), []byte("aad"), nil)

		require.NotNil(t, cipher)
		require.NotNil(t, nonce)
		require.NoError(t, err)
	})

	t.Run("Fail to encrypt a message", func(t *testing.T) {
		svc, err := kms.NewService(&kms.Config{
			StorageProvider: mockstorage.NewMockStoreProvider(),
			CryptoService:   &mockcrypto.Crypto{EncryptErr: errors.New("encrypt error")},
		})
		require.NoError(t, err)

		cipher, nonce, err := svc.Encrypt([]byte("test message"), []byte("aad"), nil)

		require.Nil(t, cipher)
		require.Nil(t, nonce)
		require.Error(t, err)
	})
}

func TestDecrypt(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		svc, err := kms.NewService(&kms.Config{
			StorageProvider: mockstorage.NewMockStoreProvider(),
			CryptoService:   &mockcrypto.Crypto{DecryptValue: []byte("plain text")},
		})
		require.NoError(t, err)

		plainText, err := svc.Decrypt([]byte("cipher"), []byte("aad"), []byte("nonce"), nil)

		require.NotNil(t, plainText)
		require.NoError(t, err)
	})

	t.Run("Fail to decrypt a cipher", func(t *testing.T) {
		svc, err := kms.NewService(&kms.Config{
			StorageProvider: mockstorage.NewMockStoreProvider(),
			CryptoService:   &mockcrypto.Crypto{DecryptErr: errors.New("decrypt error")},
		})
		require.NoError(t, err)

		plainText, err := svc.Decrypt([]byte("cipher"), []byte("aad"), []byte("nonce"), nil)

		require.Nil(t, plainText)
		require.Error(t, err)
	})
}

func TestComputeMAC(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		svc, err := kms.NewService(&kms.Config{
			StorageProvider: mockstorage.NewMockStoreProvider(),
			CryptoService:   &mockcrypto.Crypto{ComputeMACValue: []byte("mac")},
		})
		require.NoError(t, err)

		mac, err := svc.ComputeMAC([]byte("data"), nil)

		require.NotNil(t, mac)
		require.NoError(t, err)
	})

	t.Run("Fail to compute MAC for data", func(t *testing.T) {
		svc, err := kms.NewService(&kms.Config{
			StorageProvider: mockstorage.NewMockStoreProvider(),
			CryptoService:   &mockcrypto.Crypto{ComputeMACErr: errors.New("compute MAC error")},
		})
		require.NoError(t, err)

		mac, err := svc.ComputeMAC([]byte("data"), nil)

		require.Nil(t, mac)
		require.Error(t, err)
	})
}

func TestVerifyMAC(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		svc, err := kms.NewService(&kms.Config{
			StorageProvider: mockstorage.NewMockStoreProvider(),
			CryptoService:   &mockcrypto.Crypto{},
		})
		require.NoError(t, err)

		err = svc.VerifyMAC([]byte("mac"), []byte("data"), nil)

		require.NoError(t, err)
	})

	t.Run("Fail to verify MAC for data", func(t *testing.T) {
		svc, err := kms.NewService(&kms.Config{
			StorageProvider: mockstorage.NewMockStoreProvider(),
			CryptoService:   &mockcrypto.Crypto{VerifyMACErr: errors.New("verify MAC error")},
		})
		require.NoError(t, err)

		err = svc.VerifyMAC([]byte("mac"), []byte("data"), nil)

		require.Error(t, err)
	})
}

func TestWrapKey(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		svc, err := kms.NewService(&kms.Config{
			StorageProvider: mockstorage.NewMockStoreProvider(),
			CryptoService:   &mockcrypto.Crypto{WrapValue: &crypto.RecipientWrappedKey{}},
		})
		require.NoError(t, err)

		recWK, err := svc.WrapKey([]byte("cek"), []byte("apu"), []byte("apv"), &crypto.PublicKey{})

		require.NotNil(t, recWK)
		require.NoError(t, err)
	})

	t.Run("Fail to wrap a key", func(t *testing.T) {
		svc, err := kms.NewService(&kms.Config{
			StorageProvider: mockstorage.NewMockStoreProvider(),
			CryptoService:   &mockcrypto.Crypto{WrapError: errors.New("wrap error")},
		})
		require.NoError(t, err)

		recWK, err := svc.WrapKey([]byte("cek"), []byte("apu"), []byte("apv"), &crypto.PublicKey{})

		require.Nil(t, recWK)
		require.Error(t, err)
	})
}

func TestUnwrapKey(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		svc, err := kms.NewService(&kms.Config{
			StorageProvider: mockstorage.NewMockStoreProvider(),
			CryptoService:   &mockcrypto.Crypto{UnwrapValue: []byte("key")},
		})
		require.NoError(t, err)

		key, err := svc.UnwrapKey(&crypto.RecipientWrappedKey{}, nil)

		require.NotNil(t, key)
		require.NoError(t, err)
	})

	t.Run("Fail to unwrap a key", func(t *testing.T) {
		svc, err := kms.NewService(&kms.Config{
			StorageProvider: mockstorage.NewMockStoreProvider(),
			CryptoService:   &mockcrypto.Crypto{UnwrapError: errors.New("unwrap error")},
		})
		require.NoError(t, err)

		key, err := svc.UnwrapKey(&crypto.RecipientWrappedKey{}, nil)

		require.Nil(t, key)
		require.Error(t, err)
	})
}
