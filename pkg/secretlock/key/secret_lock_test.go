/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package key_test

import (
	"testing"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	ariescrypto "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	mockcrypto "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	ariesstorage "github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/kms/pkg/controller/errors"
	keysecretlock "github.com/trustbloc/kms/pkg/secretlock/key"
)

const (
	localkeyURIPrefix = "local-lock://"
	primarykeyURI     = "local-lock://primarykey"
)

func TestNew(t *testing.T) {
	t.Run("Success Encrypt", func(t *testing.T) {
		provider := &mockProvider{
			MockStorageProvider: mem.NewProvider(),
			MockSecretLock:      &noop.NoLock{},
		}

		localKMS, err := localkms.New(primarykeyURI, provider)
		require.NoError(t, err)
		require.NotNil(t, localKMS)

		keyID, _, err := localKMS.Create(kms.AES256GCM)
		require.NoError(t, err)

		crypto, err := tinkcrypto.New()
		require.NoError(t, err)

		secretLock := keysecretlock.NewLock(&secretlockProvider{
			kms:    localKMS,
			crypto: crypto,
		})

		require.NotNil(t, secretLock)

		_, err = secretLock.Encrypt(keyID, &secretlock.EncryptRequest{
			Plaintext:                   "Test payload",
			AdditionalAuthenticatedData: "",
		})
		require.NoError(t, err)
	})

	t.Run("Success Decrypt", func(t *testing.T) {
		provider := &mockProvider{
			MockStorageProvider: mem.NewProvider(),
			MockSecretLock:      &noop.NoLock{},
		}

		localKMS, err := localkms.New(primarykeyURI, provider)
		require.NoError(t, err)
		require.NotNil(t, localKMS)

		keyID, _, err := localKMS.Create(kms.AES256GCM)
		require.NoError(t, err)

		crypto, err := tinkcrypto.New()
		require.NoError(t, err)

		secretLock := keysecretlock.NewLock(&secretlockProvider{
			kms:    localKMS,
			crypto: crypto,
		})

		require.NotNil(t, secretLock)

		plaintext := "Test payload"
		encResponse, err := secretLock.Encrypt(keyID, &secretlock.EncryptRequest{
			Plaintext:                   plaintext,
			AdditionalAuthenticatedData: "",
		})
		require.NoError(t, err)

		decResponse, err := secretLock.Decrypt(keyID, &secretlock.DecryptRequest{
			Ciphertext:                  encResponse.Ciphertext,
			AdditionalAuthenticatedData: "",
		})

		require.NoError(t, err)
		require.Equal(t, plaintext, decResponse.Plaintext)
	})

	t.Run("Success user KMS Create/Get Key", func(t *testing.T) {
		provider := &mockProvider{
			MockStorageProvider: mem.NewProvider(),
			MockSecretLock:      &noop.NoLock{},
		}

		localKMS, err := localkms.New(primarykeyURI, provider)
		require.NoError(t, err)
		require.NotNil(t, localKMS)

		keyID, _, err := localKMS.Create(kms.AES256GCM)
		require.NoError(t, err)

		crypto, err := tinkcrypto.New()
		require.NoError(t, err)

		secretLock := keysecretlock.NewLock(&secretlockProvider{
			kms:    localKMS,
			crypto: crypto,
		})

		require.NotNil(t, secretLock)

		keyURI := localkeyURIPrefix + keyID

		userKMS, err := localkms.New(keyURI, &mockProvider{
			MockStorageProvider: mem.NewProvider(),
			MockSecretLock:      secretLock,
		})
		require.NoError(t, err)

		usrkeyID, _, err := userKMS.Create(kms.AES256GCM)
		require.NoError(t, err)

		_, err = userKMS.Get(usrkeyID)
		require.NoError(t, err)
	})

	t.Run("Encrypt error (Invalid key id)", func(t *testing.T) {
		provider := &mockProvider{
			MockStorageProvider: mem.NewProvider(),
			MockSecretLock:      &noop.NoLock{},
		}

		localKMS, err := localkms.New(primarykeyURI, provider)
		require.NoError(t, err)
		require.NotNil(t, localKMS)

		crypto, err := tinkcrypto.New()
		require.NoError(t, err)

		secretLock := keysecretlock.NewLock(&secretlockProvider{
			kms:    localKMS,
			crypto: crypto,
		})

		require.NotNil(t, secretLock)

		_, err = secretLock.Encrypt("Invalid key id", &secretlock.EncryptRequest{
			Plaintext:                   "Test payload",
			AdditionalAuthenticatedData: "",
		})
		require.Error(t, err)
	})

	t.Run("Encrypt error (crypto error)", func(t *testing.T) {
		provider := &mockProvider{
			MockStorageProvider: mem.NewProvider(),
			MockSecretLock:      &noop.NoLock{},
		}

		localKMS, err := localkms.New(primarykeyURI, provider)
		require.NoError(t, err)
		require.NotNil(t, localKMS)

		secretLock := keysecretlock.NewLock(&secretlockProvider{
			kms: localKMS,
			crypto: &mockcrypto.Crypto{
				EncryptErr: errors.New("crypto error"),
			},
		})
		require.NotNil(t, secretLock)

		keyID, _, err := localKMS.Create(kms.AES256GCM)
		require.NoError(t, err)

		_, err = secretLock.Encrypt(keyID, &secretlock.EncryptRequest{
			Plaintext:                   "Test payload",
			AdditionalAuthenticatedData: "",
		})
		require.EqualError(t, err, "encrypt request: crypto error")
	})

	t.Run("Decrypt error (Invalid key id)", func(t *testing.T) {
		provider := &mockProvider{
			MockStorageProvider: mem.NewProvider(),
			MockSecretLock:      &noop.NoLock{},
		}

		localKMS, err := localkms.New(primarykeyURI, provider)
		require.NoError(t, err)
		require.NotNil(t, localKMS)

		crypto, err := tinkcrypto.New()
		require.NoError(t, err)

		secretLock := keysecretlock.NewLock(&secretlockProvider{
			kms:    localKMS,
			crypto: crypto,
		})

		require.NotNil(t, secretLock)

		_, err = secretLock.Decrypt("Invalid key id", &secretlock.DecryptRequest{})
		require.Error(t, err)
	})

	t.Run("Decrypt error (Invalid Ciphertext)", func(t *testing.T) {
		provider := &mockProvider{
			MockStorageProvider: mem.NewProvider(),
			MockSecretLock:      &noop.NoLock{},
		}

		localKMS, err := localkms.New(primarykeyURI, provider)
		require.NoError(t, err)
		require.NotNil(t, localKMS)

		crypto, err := tinkcrypto.New()
		require.NoError(t, err)

		secretLock := keysecretlock.NewLock(&secretlockProvider{
			kms:    localKMS,
			crypto: crypto,
		})

		require.NotNil(t, secretLock)

		keyID, _, err := localKMS.Create(kms.AES256GCM)
		require.NoError(t, err)

		_, err = secretLock.Decrypt(keyID, &secretlock.DecryptRequest{
			Ciphertext:                  "````",
			AdditionalAuthenticatedData: "",
		})

		require.EqualError(t, err, "decode ciphertext: illegal base64 data at input byte 0")

		_, err = secretLock.Decrypt(keyID, &secretlock.DecryptRequest{
			Ciphertext:                  "",
			AdditionalAuthenticatedData: "",
		})

		require.EqualError(t, err, "decrypt request: invalid ciphertext")

		_, err = secretLock.Decrypt(keyID, &secretlock.DecryptRequest{
			Ciphertext:                  "c2hvcnR0ZXN0",
			AdditionalAuthenticatedData: "",
		})

		require.EqualError(t, err, "decrypt request: invalid ciphertext")
	})

	t.Run("Encrypt error (crypto error)", func(t *testing.T) {
		provider := &mockProvider{
			MockStorageProvider: mem.NewProvider(),
			MockSecretLock:      &noop.NoLock{},
		}

		localKMS, err := localkms.New(primarykeyURI, provider)
		require.NoError(t, err)
		require.NotNil(t, localKMS)

		keyID, _, err := localKMS.Create(kms.AES256GCM)
		require.NoError(t, err)

		crypto, err := tinkcrypto.New()
		require.NoError(t, err)

		secretLock := keysecretlock.NewLock(&secretlockProvider{
			kms:    localKMS,
			crypto: crypto,
		})

		require.NotNil(t, secretLock)

		plaintext := "Test payload"
		encResponse, err := secretLock.Encrypt(keyID, &secretlock.EncryptRequest{
			Plaintext:                   plaintext,
			AdditionalAuthenticatedData: "",
		})
		require.NoError(t, err)

		otherkeyID, _, err := localKMS.Create(kms.AES256GCM)
		require.NoError(t, err)

		_, err = secretLock.Decrypt(otherkeyID, &secretlock.DecryptRequest{
			Ciphertext:                  encResponse.Ciphertext,
			AdditionalAuthenticatedData: "",
		})

		require.EqualError(t, err, "decrypt request: decrypt cipher: decryption failed")
	})
}

type secretlockProvider struct {
	kms    kms.KeyManager
	crypto ariescrypto.Crypto
}

func (s *secretlockProvider) KMS() kms.KeyManager {
	return s.kms
}

func (s *secretlockProvider) Crypto() ariescrypto.Crypto {
	return s.crypto
}

type mockProvider struct {
	MockStorageProvider ariesstorage.Provider
	MockSecretLock      secretlock.Service
}

func (p *mockProvider) StorageProvider() ariesstorage.Provider {
	return p.MockStorageProvider
}

func (p *mockProvider) SecretLock() secretlock.Service {
	return p.MockSecretLock
}
