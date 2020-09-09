/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"errors"
	"testing"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/signature"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/stretchr/testify/require"

	mockkms "github.com/trustbloc/hub-kms/pkg/internal/mock/kms"
	"github.com/trustbloc/hub-kms/pkg/keystore"
)

const (
	testKeystoreID = "keystoreID"
	testKeyType    = kms.ED25519
	testKeyID      = "keyID"
	testMessage    = "test message"
	testSignature  = "signature"
	testAAD        = "additional data"
	testNonce      = "nonce"
	testMAC        = "mac"
)

func TestNewService(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		srv := NewService(mockkms.NewMockProvider())
		require.NotNil(t, srv)
	})
}

func TestCreateKey(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockKeystore.Store[testKeystoreID] = &keystore.Keystore{
			ID: testKeystoreID,
		}
		provider.MockKMS.CreateKeyID = testKeyID

		srv := NewService(provider)
		require.NotNil(t, srv)

		keyID, err := srv.CreateKey(testKeystoreID, testKeyType)
		require.NotEmpty(t, keyID)
		require.NoError(t, err)

		k, ok := provider.MockKeystore.Store[testKeystoreID]
		require.True(t, ok)
		require.Equal(t, keyID, k.KeyIDs[0])
	})

	t.Run("Error: key create", func(t *testing.T) {
		createKeyError := errors.New("create key error")
		provider := mockkms.NewMockProvider()
		provider.MockKMS.CreateKeyErr = createKeyError

		srv := NewService(provider)
		require.NotNil(t, srv)

		keyID, err := srv.CreateKey(testKeystoreID, testKeyType)

		require.Empty(t, keyID)
		require.Equal(t, err, &serviceError{msg: createKeyFailed, err: createKeyError})
	})

	t.Run("Error: get keystore", func(t *testing.T) {
		keystoreGetError := errors.New("get keystore error")
		provider := mockkms.NewMockProvider()
		provider.MockKeystore.ErrGet = keystoreGetError

		srv := NewService(provider)
		require.NotNil(t, srv)

		keyID, err := srv.CreateKey(testKeystoreID, testKeyType)

		require.Empty(t, keyID)
		require.Equal(t, err, &serviceError{msg: getKeystoreFailed, err: keystoreGetError})
	})

	t.Run("Error: save keystore", func(t *testing.T) {
		keystoreSaveError := errors.New("save keystore error")
		provider := mockkms.NewMockProvider()
		provider.MockKeystore.ErrSave = keystoreSaveError
		provider.MockKeystore.Store[testKeystoreID] = &keystore.Keystore{
			ID: testKeystoreID,
		}
		provider.MockKMS.CreateKeyID = testKeyID

		srv := NewService(provider)
		require.NotNil(t, srv)

		keyID, err := srv.CreateKey(testKeystoreID, testKeyType)

		require.Empty(t, keyID)
		require.Equal(t, err, &serviceError{msg: saveKeystoreFailed, err: keystoreSaveError})
	})
}

func TestSign(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockKeystore.Store[testKeystoreID] = &keystore.Keystore{
			ID:     testKeystoreID,
			KeyIDs: []string{testKeyID},
		}
		provider.MockCrypto.SignValue = []byte("signature")

		srv := NewService(provider)
		require.NotNil(t, srv)

		sig, err := srv.Sign(testKeystoreID, testKeyID, []byte(testMessage))

		require.NotEmpty(t, sig)
		require.NoError(t, err)
	})

	t.Run("Error: get keystore", func(t *testing.T) {
		keystoreGetError := errors.New("get keystore error")
		provider := mockkms.NewMockProvider()
		provider.MockKeystore.ErrGet = keystoreGetError

		srv := NewService(provider)
		require.NotNil(t, srv)

		sig, err := srv.Sign(testKeystoreID, testKeyID, []byte(testMessage))

		require.Empty(t, sig)
		require.Equal(t, err, &serviceError{msg: getKeystoreFailed, err: keystoreGetError})
	})

	t.Run("Error: no keys defined", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockKeystore.Store[testKeystoreID] = &keystore.Keystore{
			ID: testKeystoreID,
		}
		srv := NewService(provider)
		require.NotNil(t, srv)

		sig, err := srv.Sign(testKeystoreID, testKeyID, []byte(testMessage))

		require.Empty(t, sig)
		require.Equal(t, err, &serviceError{msg: noKeysFailure})
	})

	t.Run("Error: invalid key ID", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockKeystore.Store[testKeystoreID] = &keystore.Keystore{
			ID:     testKeystoreID,
			KeyIDs: []string{testKeyID},
		}
		srv := NewService(provider)
		require.NotNil(t, srv)

		sig, err := srv.Sign(testKeystoreID, "invalidKeyID", []byte(testMessage))

		require.Empty(t, sig)
		require.Equal(t, err, &serviceError{msg: invalidKeyFailure})
	})

	t.Run("Error: get key", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockKeystore.Store[testKeystoreID] = &keystore.Keystore{
			ID:     testKeystoreID,
			KeyIDs: []string{testKeyID},
		}

		getKeyErr := errors.New("get key error")
		provider.MockKMS.GetKeyErr = getKeyErr

		srv := NewService(provider)
		require.NotNil(t, srv)

		sig, err := srv.Sign(testKeystoreID, testKeyID, []byte(testMessage))

		require.Empty(t, sig)
		require.Equal(t, err, &serviceError{msg: getKeyFailed, err: getKeyErr})
	})

	t.Run("Error: sign message failed", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockKeystore.Store[testKeystoreID] = &keystore.Keystore{
			ID:     testKeystoreID,
			KeyIDs: []string{testKeyID},
		}

		signErr := errors.New("sign error")
		provider.MockCrypto.SignErr = signErr

		srv := NewService(provider)
		require.NotNil(t, srv)

		sig, err := srv.Sign(testKeystoreID, testKeyID, []byte(testMessage))

		require.Empty(t, sig)
		require.Equal(t, err, &serviceError{msg: signMessageFailed, err: signErr})
	})
}

func TestVerify(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockKeystore.Store[testKeystoreID] = &keystore.Keystore{
			ID:     testKeystoreID,
			KeyIDs: []string{testKeyID},
		}

		kh, err := keyset.NewHandle(signature.ED25519KeyTemplate())
		require.NoError(t, err)

		provider.MockKMS.GetKeyValue = kh

		srv := NewService(provider)
		require.NotNil(t, srv)

		err = srv.Verify(testKeystoreID, testKeyID, []byte(testSignature), []byte(testMessage))
		require.NoError(t, err)
	})

	t.Run("Error: get keystore", func(t *testing.T) {
		keystoreGetError := errors.New("get keystore error")
		provider := mockkms.NewMockProvider()
		provider.MockKeystore.ErrGet = keystoreGetError

		srv := NewService(provider)
		require.NotNil(t, srv)

		err := srv.Verify(testKeystoreID, testKeyID, []byte(testSignature), []byte(testMessage))
		require.Equal(t, err, &serviceError{msg: getKeystoreFailed, err: keystoreGetError})
	})

	t.Run("Error: no keys defined", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockKeystore.Store[testKeystoreID] = &keystore.Keystore{
			ID: testKeystoreID,
		}
		srv := NewService(provider)
		require.NotNil(t, srv)

		err := srv.Verify(testKeystoreID, testKeyID, []byte(testSignature), []byte(testMessage))
		require.Equal(t, err, &serviceError{msg: noKeysFailure})
	})

	t.Run("Error: invalid key ID", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockKeystore.Store[testKeystoreID] = &keystore.Keystore{
			ID:     testKeystoreID,
			KeyIDs: []string{testKeyID},
		}
		srv := NewService(provider)
		require.NotNil(t, srv)

		err := srv.Verify(testKeystoreID, "invalidKeyID", []byte(testSignature), []byte(testMessage))
		require.Equal(t, err, &serviceError{msg: invalidKeyFailure})
	})

	t.Run("Error: get key", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockKeystore.Store[testKeystoreID] = &keystore.Keystore{
			ID:     testKeystoreID,
			KeyIDs: []string{testKeyID},
		}

		getKeyError := errors.New("get key error")
		provider.MockKMS.GetKeyErr = getKeyError

		srv := NewService(provider)
		require.NotNil(t, srv)

		err := srv.Verify(testKeystoreID, testKeyID, []byte(testSignature), []byte(testMessage))
		require.Equal(t, err, &serviceError{msg: getKeyFailed, err: getKeyError})
	})

	t.Run("Error: verify with bad key handle", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockKeystore.Store[testKeystoreID] = &keystore.Keystore{
			ID:     testKeystoreID,
			KeyIDs: []string{testKeyID},
		}

		badKH, err := keyset.NewHandle(aead.KMSEnvelopeAEADKeyTemplate("badUrl", nil))
		require.NoError(t, err)

		provider.MockKMS.GetKeyValue = badKH

		srv := NewService(provider)
		require.NotNil(t, srv)

		err = srv.Verify(testKeystoreID, testKeyID, []byte(testSignature), []byte(testMessage))
		require.Error(t, err)
	})

	t.Run("Error: invalid signature", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockKeystore.Store[testKeystoreID] = &keystore.Keystore{
			ID:     testKeystoreID,
			KeyIDs: []string{testKeyID},
		}
		invalidSignatureErr := errors.New("verify msg: invalid signature")
		provider.MockCrypto.VerifyErr = invalidSignatureErr

		kh, err := keyset.NewHandle(signature.ED25519KeyTemplate())
		require.NoError(t, err)

		provider.MockKMS.GetKeyValue = kh

		srv := NewService(provider)
		require.NotNil(t, srv)

		err = srv.Verify(testKeystoreID, testKeyID, []byte(testSignature), []byte(testMessage))
		require.Equal(t, err, &serviceError{msg: verifySignatureFailed, err: invalidSignatureErr})
	})

	t.Run("Error: other verify error", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockKeystore.Store[testKeystoreID] = &keystore.Keystore{
			ID:     testKeystoreID,
			KeyIDs: []string{testKeyID},
		}
		provider.MockCrypto.VerifyErr = errors.New("other verify error")

		kh, err := keyset.NewHandle(signature.ED25519KeyTemplate())
		require.NoError(t, err)

		provider.MockKMS.GetKeyValue = kh

		srv := NewService(provider)
		require.NotNil(t, srv)

		err = srv.Verify(testKeystoreID, testKeyID, []byte(testSignature), []byte(testMessage))
		require.Error(t, err)
	})
}

func TestEncrypt(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockKeystore.Store[testKeystoreID] = &keystore.Keystore{
			ID:     testKeystoreID,
			KeyIDs: []string{testKeyID},
		}

		provider.MockCrypto.EncryptValue = []byte("cipher text")
		provider.MockCrypto.EncryptNonceValue = []byte("nonce")

		srv := NewService(provider)
		require.NotNil(t, srv)

		cipher, nonce, err := srv.Encrypt(testKeystoreID, testKeyID, []byte(testMessage), []byte(testAAD))
		require.NoError(t, err)
		require.NotEmpty(t, cipher)
		require.NotEmpty(t, nonce)
	})

	t.Run("Error: get keystore", func(t *testing.T) {
		keystoreGetError := errors.New("get keystore error")
		provider := mockkms.NewMockProvider()
		provider.MockKeystore.ErrGet = keystoreGetError

		srv := NewService(provider)
		require.NotNil(t, srv)

		cipher, nonce, err := srv.Encrypt(testKeystoreID, testKeyID, []byte(testMessage), []byte(testAAD))

		require.Empty(t, cipher)
		require.Empty(t, nonce)
		require.Equal(t, err, &serviceError{msg: getKeystoreFailed, err: keystoreGetError})
	})

	t.Run("Error: no keys defined", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockKeystore.Store[testKeystoreID] = &keystore.Keystore{
			ID: testKeystoreID,
		}
		srv := NewService(provider)
		require.NotNil(t, srv)

		cipher, nonce, err := srv.Encrypt(testKeystoreID, testKeyID, []byte(testMessage), []byte(testAAD))

		require.Empty(t, cipher)
		require.Empty(t, nonce)
		require.Equal(t, err, &serviceError{msg: noKeysFailure})
	})

	t.Run("Error: invalid key ID", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockKeystore.Store[testKeystoreID] = &keystore.Keystore{
			ID:     testKeystoreID,
			KeyIDs: []string{testKeyID},
		}
		srv := NewService(provider)
		require.NotNil(t, srv)

		cipher, nonce, err := srv.Encrypt(testKeystoreID, "invalidKeyID", []byte(testMessage), []byte(testAAD))

		require.Empty(t, cipher)
		require.Empty(t, nonce)
		require.Equal(t, err, &serviceError{msg: invalidKeyFailure})
	})

	t.Run("Error: get key", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockKeystore.Store[testKeystoreID] = &keystore.Keystore{
			ID:     testKeystoreID,
			KeyIDs: []string{testKeyID},
		}

		getKeyError := errors.New("get key error")
		provider.MockKMS.GetKeyErr = getKeyError

		srv := NewService(provider)
		require.NotNil(t, srv)

		cipher, nonce, err := srv.Encrypt(testKeystoreID, testKeyID, []byte(testMessage), []byte(testAAD))

		require.Empty(t, cipher)
		require.Empty(t, nonce)
		require.Equal(t, err, &serviceError{msg: getKeyFailed, err: getKeyError})
	})

	t.Run("Error: encrypt message failed", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockKeystore.Store[testKeystoreID] = &keystore.Keystore{
			ID:     testKeystoreID,
			KeyIDs: []string{testKeyID},
		}

		encryptErr := errors.New("encrypt error")
		provider.MockCrypto.EncryptErr = encryptErr

		srv := NewService(provider)
		require.NotNil(t, srv)

		cipher, nonce, err := srv.Encrypt(testKeystoreID, testKeyID, []byte(testMessage), []byte(testAAD))

		require.Empty(t, cipher)
		require.Empty(t, nonce)
		require.Equal(t, err, &serviceError{msg: encryptMessageFailed, err: encryptErr})
	})
}

func TestDecrypt(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockKeystore.Store[testKeystoreID] = &keystore.Keystore{
			ID:     testKeystoreID,
			KeyIDs: []string{testKeyID},
		}

		provider.MockCrypto.DecryptValue = []byte("plain text")

		srv := NewService(provider)
		require.NotNil(t, srv)

		plain, err := srv.Decrypt(testKeystoreID, testKeyID, []byte(testMessage), []byte(testAAD), []byte(testNonce))

		require.NotEmpty(t, plain)
		require.NoError(t, err)
	})

	t.Run("Error: get keystore", func(t *testing.T) {
		keystoreGetError := errors.New("get keystore error")
		provider := mockkms.NewMockProvider()
		provider.MockKeystore.ErrGet = keystoreGetError

		srv := NewService(provider)
		require.NotNil(t, srv)

		plain, err := srv.Decrypt(testKeystoreID, testKeyID, []byte(testMessage), []byte(testAAD), []byte(testNonce))

		require.Empty(t, plain)
		require.Equal(t, err, &serviceError{msg: getKeystoreFailed, err: keystoreGetError})
	})

	t.Run("Error: no keys defined", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockKeystore.Store[testKeystoreID] = &keystore.Keystore{
			ID: testKeystoreID,
		}
		srv := NewService(provider)
		require.NotNil(t, srv)

		plain, err := srv.Decrypt(testKeystoreID, testKeyID, []byte(testMessage), []byte(testAAD), []byte(testNonce))

		require.Empty(t, plain)
		require.Equal(t, err, &serviceError{msg: noKeysFailure})
	})

	t.Run("Error: invalid key ID", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockKeystore.Store[testKeystoreID] = &keystore.Keystore{
			ID:     testKeystoreID,
			KeyIDs: []string{testKeyID},
		}
		srv := NewService(provider)
		require.NotNil(t, srv)

		plain, err := srv.Decrypt(testKeystoreID, "invalidKeyID", []byte(testMessage), []byte(testAAD), []byte(testNonce))

		require.Empty(t, plain)
		require.Equal(t, err, &serviceError{msg: invalidKeyFailure})
	})

	t.Run("Error: get key", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockKeystore.Store[testKeystoreID] = &keystore.Keystore{
			ID:     testKeystoreID,
			KeyIDs: []string{testKeyID},
		}

		getKeyError := errors.New("get key error")
		provider.MockKMS.GetKeyErr = getKeyError

		srv := NewService(provider)
		require.NotNil(t, srv)

		plain, err := srv.Decrypt(testKeystoreID, testKeyID, []byte(testMessage), []byte(testAAD), []byte(testNonce))

		require.Empty(t, plain)
		require.Equal(t, err, &serviceError{msg: getKeyFailed, err: getKeyError})
	})

	t.Run("Error: decrypt cipher failed", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockKeystore.Store[testKeystoreID] = &keystore.Keystore{
			ID:     testKeystoreID,
			KeyIDs: []string{testKeyID},
		}

		decryptErr := errors.New("decrypt error")
		provider.MockCrypto.DecryptErr = decryptErr

		srv := NewService(provider)
		require.NotNil(t, srv)

		plain, err := srv.Decrypt(testKeystoreID, testKeyID, []byte(testMessage), []byte(testAAD), []byte(testNonce))

		require.Empty(t, plain)
		require.Equal(t, err, &serviceError{msg: decryptCipherFailed, err: decryptErr})
	})
}

func TestComputeMAC(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockKeystore.Store[testKeystoreID] = &keystore.Keystore{
			ID:     testKeystoreID,
			KeyIDs: []string{testKeyID},
		}
		provider.MockCrypto.ComputeMACValue = []byte("mac value")

		srv := NewService(provider)
		require.NotNil(t, srv)

		sig, err := srv.ComputeMAC(testKeystoreID, testKeyID, []byte(testMessage))

		require.NotEmpty(t, sig)
		require.NoError(t, err)
	})

	t.Run("Error: get keystore", func(t *testing.T) {
		keystoreGetError := errors.New("get keystore error")
		provider := mockkms.NewMockProvider()
		provider.MockKeystore.ErrGet = keystoreGetError

		srv := NewService(provider)
		require.NotNil(t, srv)

		sig, err := srv.ComputeMAC(testKeystoreID, testKeyID, []byte(testMessage))

		require.Empty(t, sig)
		require.Equal(t, err, &serviceError{msg: getKeystoreFailed, err: keystoreGetError})
	})

	t.Run("Error: no keys defined", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockKeystore.Store[testKeystoreID] = &keystore.Keystore{
			ID: testKeystoreID,
		}
		srv := NewService(provider)
		require.NotNil(t, srv)

		sig, err := srv.ComputeMAC(testKeystoreID, testKeyID, []byte(testMessage))

		require.Empty(t, sig)
		require.Equal(t, err, &serviceError{msg: noKeysFailure})
	})

	t.Run("Error: invalid key ID", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockKeystore.Store[testKeystoreID] = &keystore.Keystore{
			ID:     testKeystoreID,
			KeyIDs: []string{testKeyID},
		}
		srv := NewService(provider)
		require.NotNil(t, srv)

		sig, err := srv.ComputeMAC(testKeystoreID, "invalidKeyID", []byte(testMessage))

		require.Empty(t, sig)
		require.Equal(t, err, &serviceError{msg: invalidKeyFailure})
	})

	t.Run("Error: get key", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockKeystore.Store[testKeystoreID] = &keystore.Keystore{
			ID:     testKeystoreID,
			KeyIDs: []string{testKeyID},
		}

		getKeyError := errors.New("get key error")
		provider.MockKMS.GetKeyErr = getKeyError

		srv := NewService(provider)
		require.NotNil(t, srv)

		sig, err := srv.ComputeMAC(testKeystoreID, testKeyID, []byte(testMessage))

		require.Empty(t, sig)
		require.Equal(t, err, &serviceError{msg: getKeyFailed, err: getKeyError})
	})

	t.Run("Error: compute MAC failed", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockKeystore.Store[testKeystoreID] = &keystore.Keystore{
			ID:     testKeystoreID,
			KeyIDs: []string{testKeyID},
		}

		computeMACErr := errors.New("compute MAC error")
		provider.MockCrypto.ComputeMACErr = computeMACErr

		srv := NewService(provider)
		require.NotNil(t, srv)

		sig, err := srv.ComputeMAC(testKeystoreID, testKeyID, []byte(testMessage))

		require.Empty(t, sig)
		require.Equal(t, err, &serviceError{msg: computeMACFailed, err: computeMACErr})
	})
}

func TestVerifyMAC(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockKeystore.Store[testKeystoreID] = &keystore.Keystore{
			ID:     testKeystoreID,
			KeyIDs: []string{testKeyID},
		}

		kh, err := keyset.NewHandle(signature.ED25519KeyTemplate())
		require.NoError(t, err)

		provider.MockKMS.GetKeyValue = kh

		srv := NewService(provider)
		require.NotNil(t, srv)

		err = srv.VerifyMAC(testKeystoreID, testKeyID, []byte(testMAC), []byte(testMessage))
		require.NoError(t, err)
	})

	t.Run("Error: get keystore", func(t *testing.T) {
		keystoreGetError := errors.New("get keystore error")
		provider := mockkms.NewMockProvider()
		provider.MockKeystore.ErrGet = keystoreGetError

		srv := NewService(provider)
		require.NotNil(t, srv)

		err := srv.VerifyMAC(testKeystoreID, testKeyID, []byte(testMAC), []byte(testMessage))
		require.Equal(t, err, &serviceError{msg: getKeystoreFailed, err: keystoreGetError})
	})

	t.Run("Error: no keys defined", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockKeystore.Store[testKeystoreID] = &keystore.Keystore{
			ID: testKeystoreID,
		}
		srv := NewService(provider)
		require.NotNil(t, srv)

		err := srv.VerifyMAC(testKeystoreID, testKeyID, []byte(testMAC), []byte(testMessage))
		require.Equal(t, err, &serviceError{msg: noKeysFailure})
	})

	t.Run("Error: invalid key ID", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockKeystore.Store[testKeystoreID] = &keystore.Keystore{
			ID:     testKeystoreID,
			KeyIDs: []string{testKeyID},
		}
		srv := NewService(provider)
		require.NotNil(t, srv)

		err := srv.VerifyMAC(testKeystoreID, "invalidKeyID", []byte(testMAC), []byte(testMessage))
		require.Equal(t, err, &serviceError{msg: invalidKeyFailure})
	})

	t.Run("Error: get key", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockKeystore.Store[testKeystoreID] = &keystore.Keystore{
			ID:     testKeystoreID,
			KeyIDs: []string{testKeyID},
		}

		getKeyError := errors.New("get key error")
		provider.MockKMS.GetKeyErr = getKeyError

		srv := NewService(provider)
		require.NotNil(t, srv)

		err := srv.VerifyMAC(testKeystoreID, testKeyID, []byte(testMAC), []byte(testMessage))
		require.Equal(t, err, &serviceError{msg: getKeyFailed, err: getKeyError})
	})

	t.Run("Error: verify MAC failed", func(t *testing.T) {
		provider := mockkms.NewMockProvider()
		provider.MockKeystore.Store[testKeystoreID] = &keystore.Keystore{
			ID:     testKeystoreID,
			KeyIDs: []string{testKeyID},
		}

		kh, err := keyset.NewHandle(signature.ED25519KeyTemplate())
		require.NoError(t, err)
		provider.MockKMS.GetKeyValue = kh

		verifyMACErr := errors.New("verify MAC error")
		provider.MockCrypto.VerifyMACErr = verifyMACErr

		srv := NewService(provider)
		require.NotNil(t, srv)

		err = srv.VerifyMAC(testKeystoreID, testKeyID, []byte(testMAC), []byte(testMessage))
		require.Equal(t, err, &serviceError{msg: verifyMACFailed, err: verifyMACErr})
	})
}
