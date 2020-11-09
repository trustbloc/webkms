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
	arieskms "github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/stretchr/testify/require"

	mockkms "github.com/trustbloc/hub-kms/pkg/internal/mock/kms"
	"github.com/trustbloc/hub-kms/pkg/keystore"
	"github.com/trustbloc/hub-kms/pkg/kms"
)

const (
	testKeystoreID = "keystoreID"
	testKeyID      = "keyID"
	testKeyType    = arieskms.ED25519
	testMessage    = "test message"
	testSignature  = "signature"
	testAAD        = "additional data"
	testNonce      = "nonce"
	testMAC        = "mac"
)

func TestNewService(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		srv := kms.NewService(mockkms.NewMockProvider())
		require.NotNil(t, srv)
	})
}

func TestCreateKey(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockKeyManager.CreateKeyID = testKeyID

		k := &keystore.Keystore{
			ID: testKeystoreID,
		}
		provider.MockKeystoreService.GetKeystore = k

		srv := kms.NewService(provider)
		require.NotNil(t, srv)

		keyID, err := srv.CreateKey(testKeystoreID, testKeyType)
		require.Equal(t, testKeyID, keyID)
		require.NoError(t, err)

		require.Contains(t, k.OperationalKeyIDs, keyID)
	})

	t.Run("Error: key create", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockKeyManager.CreateKeyErr = errors.New("create key error")

		srv := kms.NewService(provider)
		require.NotNil(t, srv)

		keyID, err := srv.CreateKey(testKeystoreID, testKeyType)

		require.Empty(t, keyID)
		require.Error(t, err)
		require.Equal(t, "create key failed: create key error", err.Error())
	})

	t.Run("Error: get keystore", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockKeystoreService.GetErr = errors.New("get keystore error")

		srv := kms.NewService(provider)
		require.NotNil(t, srv)

		keyID, err := srv.CreateKey(testKeystoreID, testKeyType)

		require.Empty(t, keyID)
		require.Error(t, err)
		require.Equal(t, "get keystore failed: get keystore error", err.Error())
	})

	t.Run("Error: save keystore", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockKeyManager.CreateKeyID = testKeyID

		k := &keystore.Keystore{
			ID: testKeystoreID,
		}
		provider.MockKeystoreService.GetKeystore = k
		provider.MockKeystoreService.SaveErr = errors.New("save keystore error")

		srv := kms.NewService(provider)
		require.NotNil(t, srv)

		keyID, err := srv.CreateKey(testKeystoreID, testKeyType)

		require.Empty(t, keyID)
		require.Error(t, err)
		require.Equal(t, "save keystore failed: save keystore error", err.Error())
	})
}

func TestSign(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockCrypto.SignValue = []byte("signature")

		k := &keystore.Keystore{
			ID:                testKeystoreID,
			OperationalKeyIDs: []string{testKeyID},
		}
		provider.MockKeystoreService.GetKeystore = k

		srv := kms.NewService(provider)
		require.NotNil(t, srv)

		sig, err := srv.Sign(testKeystoreID, testKeyID, []byte(testMessage))

		require.NotEmpty(t, sig)
		require.NoError(t, err)
	})

	t.Run("Error: get keystore", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockKeystoreService.GetErr = errors.New("get keystore error")

		srv := kms.NewService(provider)
		require.NotNil(t, srv)

		sig, err := srv.Sign(testKeystoreID, testKeyID, []byte(testMessage))

		require.Empty(t, sig)
		require.Error(t, err)
		require.Equal(t, "get keystore failed: get keystore error", err.Error())
	})

	t.Run("Error: no keys defined", func(t *testing.T) {
		provider := mockkms.NewMockProvider()

		k := &keystore.Keystore{
			ID: testKeystoreID,
		}
		provider.MockKeystoreService.GetKeystore = k

		srv := kms.NewService(provider)
		require.NotNil(t, srv)

		sig, err := srv.Sign(testKeystoreID, testKeyID, []byte(testMessage))

		require.Empty(t, sig)
		require.Error(t, err)
		require.Equal(t, "no keys defined", err.Error())
	})

	t.Run("Error: invalid key ID", func(t *testing.T) {
		provider := mockkms.NewMockProvider()

		k := &keystore.Keystore{
			ID:                testKeystoreID,
			OperationalKeyIDs: []string{testKeyID},
		}
		provider.MockKeystoreService.GetKeystore = k

		srv := kms.NewService(provider)
		require.NotNil(t, srv)

		sig, err := srv.Sign(testKeystoreID, "invalidKeyID", []byte(testMessage))

		require.Empty(t, sig)
		require.Error(t, err)
		require.Equal(t, "invalid key", err.Error())
	})

	t.Run("Error: get key", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockKeyManager.GetKeyErr = errors.New("get key error")

		k := &keystore.Keystore{
			ID:                testKeystoreID,
			OperationalKeyIDs: []string{testKeyID},
		}
		provider.MockKeystoreService.GetKeystore = k

		srv := kms.NewService(provider)
		require.NotNil(t, srv)

		sig, err := srv.Sign(testKeystoreID, testKeyID, []byte(testMessage))

		require.Empty(t, sig)
		require.Error(t, err)
		require.Equal(t, "get key failed: get key error", err.Error())
	})

	t.Run("Error: sign message failed", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockCrypto.SignErr = errors.New("sign error")

		k := &keystore.Keystore{
			ID:                testKeystoreID,
			OperationalKeyIDs: []string{testKeyID},
		}
		provider.MockKeystoreService.GetKeystore = k

		srv := kms.NewService(provider)
		require.NotNil(t, srv)

		sig, err := srv.Sign(testKeystoreID, testKeyID, []byte(testMessage))

		require.Empty(t, sig)
		require.Error(t, err)
		require.Equal(t, "sign message failed: sign error", err.Error())
	})
}

func TestVerify(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider := mockkms.NewMockProvider()

		kh, err := keyset.NewHandle(signature.ED25519KeyTemplate())
		require.NoError(t, err)
		provider.MockKeyManager.GetKeyValue = kh

		k := &keystore.Keystore{
			ID:                testKeystoreID,
			OperationalKeyIDs: []string{testKeyID},
		}
		provider.MockKeystoreService.GetKeystore = k

		srv := kms.NewService(provider)
		require.NotNil(t, srv)

		err = srv.Verify(testKeystoreID, testKeyID, []byte(testSignature), []byte(testMessage))
		require.NoError(t, err)
	})

	t.Run("Error: get keystore", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockKeystoreService.GetErr = errors.New("get keystore error")

		srv := kms.NewService(provider)
		require.NotNil(t, srv)

		err := srv.Verify(testKeystoreID, testKeyID, []byte(testSignature), []byte(testMessage))
		require.Error(t, err)
		require.Equal(t, "get keystore failed: get keystore error", err.Error())
	})

	t.Run("Error: no keys defined", func(t *testing.T) {
		provider := mockkms.NewMockProvider()

		k := &keystore.Keystore{
			ID: testKeystoreID,
		}
		provider.MockKeystoreService.GetKeystore = k

		srv := kms.NewService(provider)
		require.NotNil(t, srv)

		err := srv.Verify(testKeystoreID, testKeyID, []byte(testSignature), []byte(testMessage))
		require.Error(t, err)
		require.Equal(t, "no keys defined", err.Error())
	})

	t.Run("Error: invalid key ID", func(t *testing.T) {
		provider := mockkms.NewMockProvider()

		k := &keystore.Keystore{
			ID:                testKeystoreID,
			OperationalKeyIDs: []string{testKeyID},
		}
		provider.MockKeystoreService.GetKeystore = k

		srv := kms.NewService(provider)
		require.NotNil(t, srv)

		err := srv.Verify(testKeystoreID, "invalidKeyID", []byte(testSignature), []byte(testMessage))
		require.Error(t, err)
		require.Equal(t, "invalid key", err.Error())
	})

	t.Run("Error: get key", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockKeyManager.GetKeyErr = errors.New("get key error")

		k := &keystore.Keystore{
			ID:                testKeystoreID,
			OperationalKeyIDs: []string{testKeyID},
		}
		provider.MockKeystoreService.GetKeystore = k

		srv := kms.NewService(provider)
		require.NotNil(t, srv)

		err := srv.Verify(testKeystoreID, testKeyID, []byte(testSignature), []byte(testMessage))
		require.Error(t, err)
		require.Equal(t, "get key failed: get key error", err.Error())
	})

	t.Run("Error: verify with bad key handle", func(t *testing.T) {
		provider := mockkms.NewMockProvider()

		badKH, err := keyset.NewHandle(aead.KMSEnvelopeAEADKeyTemplate("badUrl", nil))
		require.NoError(t, err)
		provider.MockKeyManager.GetKeyValue = badKH

		k := &keystore.Keystore{
			ID:                testKeystoreID,
			OperationalKeyIDs: []string{testKeyID},
		}
		provider.MockKeystoreService.GetKeystore = k

		srv := kms.NewService(provider)
		require.NotNil(t, srv)

		err = srv.Verify(testKeystoreID, testKeyID, []byte(testSignature), []byte(testMessage))
		require.Error(t, err)
	})

	t.Run("Error: invalid signature", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockCrypto.VerifyErr = errors.New("verify msg: invalid signature")

		k := &keystore.Keystore{
			ID:                testKeystoreID,
			OperationalKeyIDs: []string{testKeyID},
		}
		provider.MockKeystoreService.GetKeystore = k

		kh, err := keyset.NewHandle(signature.ED25519KeyTemplate())
		require.NoError(t, err)
		provider.MockKeyManager.GetKeyValue = kh

		srv := kms.NewService(provider)
		require.NotNil(t, srv)

		err = srv.Verify(testKeystoreID, testKeyID, []byte(testSignature), []byte(testMessage))
		require.Error(t, err)
		require.Equal(t, "verify signature failed: verify msg: invalid signature", err.Error())
	})

	t.Run("Error: other verify error", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockCrypto.VerifyErr = errors.New("other verify error")

		k := &keystore.Keystore{
			ID:                testKeystoreID,
			OperationalKeyIDs: []string{testKeyID},
		}
		provider.MockKeystoreService.GetKeystore = k

		kh, err := keyset.NewHandle(signature.ED25519KeyTemplate())
		require.NoError(t, err)
		provider.MockKeyManager.GetKeyValue = kh

		srv := kms.NewService(provider)
		require.NotNil(t, srv)

		err = srv.Verify(testKeystoreID, testKeyID, []byte(testSignature), []byte(testMessage))
		require.Error(t, err)
	})
}

func TestEncrypt(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockCrypto.EncryptValue = []byte("cipher text")
		provider.MockCrypto.EncryptNonceValue = []byte("nonce")

		k := &keystore.Keystore{
			ID:                testKeystoreID,
			OperationalKeyIDs: []string{testKeyID},
		}
		provider.MockKeystoreService.GetKeystore = k

		srv := kms.NewService(provider)
		require.NotNil(t, srv)

		cipher, nonce, err := srv.Encrypt(testKeystoreID, testKeyID, []byte(testMessage), []byte(testAAD))
		require.NoError(t, err)
		require.NotEmpty(t, cipher)
		require.NotEmpty(t, nonce)
	})

	t.Run("Error: get keystore", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockKeystoreService.GetErr = errors.New("get keystore error")

		srv := kms.NewService(provider)
		require.NotNil(t, srv)

		cipher, nonce, err := srv.Encrypt(testKeystoreID, testKeyID, []byte(testMessage), []byte(testAAD))

		require.Empty(t, cipher)
		require.Empty(t, nonce)
		require.Error(t, err)
		require.Equal(t, "get keystore failed: get keystore error", err.Error())
	})

	t.Run("Error: no keys defined", func(t *testing.T) {
		provider := mockkms.NewMockProvider()

		k := &keystore.Keystore{
			ID: testKeystoreID,
		}
		provider.MockKeystoreService.GetKeystore = k

		srv := kms.NewService(provider)
		require.NotNil(t, srv)

		cipher, nonce, err := srv.Encrypt(testKeystoreID, testKeyID, []byte(testMessage), []byte(testAAD))

		require.Empty(t, cipher)
		require.Empty(t, nonce)
		require.Error(t, err)
		require.Equal(t, "no keys defined", err.Error())
	})

	t.Run("Error: invalid key ID", func(t *testing.T) {
		provider := mockkms.NewMockProvider()

		k := &keystore.Keystore{
			ID:                testKeystoreID,
			OperationalKeyIDs: []string{testKeyID},
		}
		provider.MockKeystoreService.GetKeystore = k

		srv := kms.NewService(provider)
		require.NotNil(t, srv)

		cipher, nonce, err := srv.Encrypt(testKeystoreID, "invalidKeyID", []byte(testMessage), []byte(testAAD))

		require.Empty(t, cipher)
		require.Empty(t, nonce)
		require.Error(t, err)
		require.Equal(t, "invalid key", err.Error())
	})

	t.Run("Error: get key", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockKeyManager.GetKeyErr = errors.New("get key error")

		k := &keystore.Keystore{
			ID:                testKeystoreID,
			OperationalKeyIDs: []string{testKeyID},
		}
		provider.MockKeystoreService.GetKeystore = k

		srv := kms.NewService(provider)
		require.NotNil(t, srv)

		cipher, nonce, err := srv.Encrypt(testKeystoreID, testKeyID, []byte(testMessage), []byte(testAAD))

		require.Empty(t, cipher)
		require.Empty(t, nonce)
		require.Error(t, err)
		require.Equal(t, "get key failed: get key error", err.Error())
	})

	t.Run("Error: encrypt message failed", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockCrypto.EncryptErr = errors.New("encrypt error")

		k := &keystore.Keystore{
			ID:                testKeystoreID,
			OperationalKeyIDs: []string{testKeyID},
		}
		provider.MockKeystoreService.GetKeystore = k

		srv := kms.NewService(provider)
		require.NotNil(t, srv)

		cipher, nonce, err := srv.Encrypt(testKeystoreID, testKeyID, []byte(testMessage), []byte(testAAD))

		require.Empty(t, cipher)
		require.Empty(t, nonce)
		require.Error(t, err)
		require.Equal(t, "encrypt message failed: encrypt error", err.Error())
	})
}

func TestDecrypt(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockCrypto.DecryptValue = []byte("plain text")

		k := &keystore.Keystore{
			ID:                testKeystoreID,
			OperationalKeyIDs: []string{testKeyID},
		}
		provider.MockKeystoreService.GetKeystore = k

		srv := kms.NewService(provider)
		require.NotNil(t, srv)

		plain, err := srv.Decrypt(testKeystoreID, testKeyID, []byte(testMessage), []byte(testAAD), []byte(testNonce))

		require.NotEmpty(t, plain)
		require.NoError(t, err)
	})

	t.Run("Error: get keystore", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockKeystoreService.GetErr = errors.New("get keystore error")

		srv := kms.NewService(provider)
		require.NotNil(t, srv)

		plain, err := srv.Decrypt(testKeystoreID, testKeyID, []byte(testMessage), []byte(testAAD), []byte(testNonce))

		require.Empty(t, plain)
		require.Error(t, err)
		require.Equal(t, "get keystore failed: get keystore error", err.Error())
	})

	t.Run("Error: no keys defined", func(t *testing.T) {
		provider := mockkms.NewMockProvider()

		k := &keystore.Keystore{
			ID: testKeystoreID,
		}
		provider.MockKeystoreService.GetKeystore = k

		srv := kms.NewService(provider)
		require.NotNil(t, srv)

		plain, err := srv.Decrypt(testKeystoreID, testKeyID, []byte(testMessage), []byte(testAAD), []byte(testNonce))

		require.Empty(t, plain)
		require.Error(t, err)
		require.Equal(t, "no keys defined", err.Error())
	})

	t.Run("Error: invalid key ID", func(t *testing.T) {
		provider := mockkms.NewMockProvider()

		k := &keystore.Keystore{
			ID:                testKeystoreID,
			OperationalKeyIDs: []string{testKeyID},
		}
		provider.MockKeystoreService.GetKeystore = k

		srv := kms.NewService(provider)
		require.NotNil(t, srv)

		plain, err := srv.Decrypt(testKeystoreID, "invalidKeyID", []byte(testMessage), []byte(testAAD), []byte(testNonce))

		require.Empty(t, plain)
		require.Error(t, err)
		require.Equal(t, "invalid key", err.Error())
	})

	t.Run("Error: get key", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockKeyManager.GetKeyErr = errors.New("get key error")

		k := &keystore.Keystore{
			ID:                testKeystoreID,
			OperationalKeyIDs: []string{testKeyID},
		}
		provider.MockKeystoreService.GetKeystore = k

		srv := kms.NewService(provider)
		require.NotNil(t, srv)

		plain, err := srv.Decrypt(testKeystoreID, testKeyID, []byte(testMessage), []byte(testAAD), []byte(testNonce))

		require.Empty(t, plain)
		require.Error(t, err)
		require.Equal(t, "get key failed: get key error", err.Error())
	})

	t.Run("Error: decrypt cipher failed", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockCrypto.DecryptErr = errors.New("decrypt error")

		k := &keystore.Keystore{
			ID:                testKeystoreID,
			OperationalKeyIDs: []string{testKeyID},
		}
		provider.MockKeystoreService.GetKeystore = k

		srv := kms.NewService(provider)
		require.NotNil(t, srv)

		plain, err := srv.Decrypt(testKeystoreID, testKeyID, []byte(testMessage), []byte(testAAD), []byte(testNonce))

		require.Empty(t, plain)
		require.Error(t, err)
		require.Equal(t, "decrypt cipher failed: decrypt error", err.Error())
	})
}

func TestComputeMAC(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockCrypto.ComputeMACValue = []byte("mac value")

		k := &keystore.Keystore{
			ID:                testKeystoreID,
			OperationalKeyIDs: []string{testKeyID},
		}
		provider.MockKeystoreService.GetKeystore = k

		srv := kms.NewService(provider)
		require.NotNil(t, srv)

		sig, err := srv.ComputeMAC(testKeystoreID, testKeyID, []byte(testMessage))

		require.NotEmpty(t, sig)
		require.NoError(t, err)
	})

	t.Run("Error: get keystore", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockKeystoreService.GetErr = errors.New("get keystore error")

		srv := kms.NewService(provider)
		require.NotNil(t, srv)

		sig, err := srv.ComputeMAC(testKeystoreID, testKeyID, []byte(testMessage))

		require.Empty(t, sig)
		require.Error(t, err)
		require.Equal(t, "get keystore failed: get keystore error", err.Error())
	})

	t.Run("Error: no keys defined", func(t *testing.T) {
		provider := mockkms.NewMockProvider()

		k := &keystore.Keystore{
			ID: testKeystoreID,
		}
		provider.MockKeystoreService.GetKeystore = k

		srv := kms.NewService(provider)
		require.NotNil(t, srv)

		sig, err := srv.ComputeMAC(testKeystoreID, testKeyID, []byte(testMessage))

		require.Empty(t, sig)
		require.Error(t, err)
		require.Equal(t, "no keys defined", err.Error())
	})

	t.Run("Error: invalid key ID", func(t *testing.T) {
		provider := mockkms.NewMockProvider()

		k := &keystore.Keystore{
			ID:                testKeystoreID,
			OperationalKeyIDs: []string{testKeyID},
		}
		provider.MockKeystoreService.GetKeystore = k

		srv := kms.NewService(provider)
		require.NotNil(t, srv)

		sig, err := srv.ComputeMAC(testKeystoreID, "invalidKeyID", []byte(testMessage))

		require.Empty(t, sig)
		require.Error(t, err)
		require.Equal(t, "invalid key", err.Error())
	})

	t.Run("Error: get key", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockKeyManager.GetKeyErr = errors.New("get key error")

		k := &keystore.Keystore{
			ID:                testKeystoreID,
			OperationalKeyIDs: []string{testKeyID},
		}
		provider.MockKeystoreService.GetKeystore = k

		srv := kms.NewService(provider)
		require.NotNil(t, srv)

		sig, err := srv.ComputeMAC(testKeystoreID, testKeyID, []byte(testMessage))

		require.Empty(t, sig)
		require.Error(t, err)
		require.Equal(t, "get key failed: get key error", err.Error())
	})

	t.Run("Error: compute MAC failed", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockCrypto.ComputeMACErr = errors.New("compute MAC error")

		k := &keystore.Keystore{
			ID:                testKeystoreID,
			OperationalKeyIDs: []string{testKeyID},
		}
		provider.MockKeystoreService.GetKeystore = k

		srv := kms.NewService(provider)
		require.NotNil(t, srv)

		sig, err := srv.ComputeMAC(testKeystoreID, testKeyID, []byte(testMessage))

		require.Empty(t, sig)
		require.Error(t, err)
		require.Equal(t, "compute MAC failed: compute MAC error", err.Error())
	})
}

func TestVerifyMAC(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider := mockkms.NewMockProvider()

		k := &keystore.Keystore{
			ID:                testKeystoreID,
			OperationalKeyIDs: []string{testKeyID},
		}
		provider.MockKeystoreService.GetKeystore = k

		kh, err := keyset.NewHandle(signature.ED25519KeyTemplate())
		require.NoError(t, err)
		provider.MockKeyManager.GetKeyValue = kh

		srv := kms.NewService(provider)
		require.NotNil(t, srv)

		err = srv.VerifyMAC(testKeystoreID, testKeyID, []byte(testMAC), []byte(testMessage))
		require.NoError(t, err)
	})

	t.Run("Error: get keystore", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockKeystoreService.GetErr = errors.New("get keystore error")

		srv := kms.NewService(provider)
		require.NotNil(t, srv)

		err := srv.VerifyMAC(testKeystoreID, testKeyID, []byte(testMAC), []byte(testMessage))
		require.Error(t, err)
		require.Equal(t, "get keystore failed: get keystore error", err.Error())
	})

	t.Run("Error: no keys defined", func(t *testing.T) {
		provider := mockkms.NewMockProvider()

		k := &keystore.Keystore{
			ID: testKeystoreID,
		}
		provider.MockKeystoreService.GetKeystore = k

		srv := kms.NewService(provider)
		require.NotNil(t, srv)

		err := srv.VerifyMAC(testKeystoreID, testKeyID, []byte(testMAC), []byte(testMessage))
		require.Error(t, err)
		require.Equal(t, "no keys defined", err.Error())
	})

	t.Run("Error: invalid key ID", func(t *testing.T) {
		provider := mockkms.NewMockProvider()

		k := &keystore.Keystore{
			ID:                testKeystoreID,
			OperationalKeyIDs: []string{testKeyID},
		}
		provider.MockKeystoreService.GetKeystore = k

		srv := kms.NewService(provider)
		require.NotNil(t, srv)

		err := srv.VerifyMAC(testKeystoreID, "invalidKeyID", []byte(testMAC), []byte(testMessage))
		require.Error(t, err)
		require.Equal(t, "invalid key", err.Error())
	})

	t.Run("Error: get key", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockKeyManager.GetKeyErr = errors.New("get key error")

		k := &keystore.Keystore{
			ID:                testKeystoreID,
			OperationalKeyIDs: []string{testKeyID},
		}
		provider.MockKeystoreService.GetKeystore = k

		srv := kms.NewService(provider)
		require.NotNil(t, srv)

		err := srv.VerifyMAC(testKeystoreID, testKeyID, []byte(testMAC), []byte(testMessage))
		require.Error(t, err)
		require.Equal(t, "get key failed: get key error", err.Error())
	})

	t.Run("Error: verify MAC failed", func(t *testing.T) {
		provider := mockkms.NewMockProvider()

		k := &keystore.Keystore{
			ID:                testKeystoreID,
			OperationalKeyIDs: []string{testKeyID},
		}
		provider.MockKeystoreService.GetKeystore = k

		kh, err := keyset.NewHandle(signature.ED25519KeyTemplate())
		require.NoError(t, err)
		provider.MockKeyManager.GetKeyValue = kh

		verifyMACErr := errors.New("verify MAC error")
		provider.MockCrypto.VerifyMACErr = verifyMACErr

		srv := kms.NewService(provider)
		require.NotNil(t, srv)

		err = srv.VerifyMAC(testKeystoreID, testKeyID, []byte(testMAC), []byte(testMessage))
		require.Error(t, err)
		require.Equal(t, "verify MAC failed: verify MAC error", err.Error())
	})
}
