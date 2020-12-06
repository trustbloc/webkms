/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"github.com/google/tink/go/keyset"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/keyio"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/trustbloc/hub-kms/pkg/keystore"
)

// Service provides kms/crypto functionality.
type Service interface {
	CreateKey(keystoreID string, kt kms.KeyType) (string, error)
	ExportKey(keystoreID, keyID string) ([]byte, error)
	Sign(keystoreID, keyID string, msg []byte) ([]byte, error)
	Verify(keystoreID, keyID string, sig, msg []byte) error
	Encrypt(keystoreID, keyID string, msg, aad []byte) ([]byte, []byte, error)
	Decrypt(keystoreID, keyID string, cipher, aad, nonce []byte) ([]byte, error)
	ComputeMAC(keystoreID, keyID string, data []byte) ([]byte, error)
	VerifyMAC(keystoreID, keyID string, mac, data []byte) error
	WrapKey(keystoreID, keyID string, cek, apu, apv []byte,
		recipientPubKey *crypto.PublicKey) (*crypto.RecipientWrappedKey, error)
	UnwrapKey(keystoreID, keyID string, recipientWK *crypto.RecipientWrappedKey,
		senderPubKey *crypto.PublicKey) ([]byte, error)

	// CryptoBox operations.
	Easy(keystoreID, keyID string, payload, nonce, theirPub []byte) ([]byte, error)
	EasyOpen(keystoreID string, cipherText, nonce, theirPub, myPub []byte) ([]byte, error)
	SealOpen(keystoreID string, cipher, myPub []byte) ([]byte, error)
}

// CryptoBox provides an elliptic-curve-based authenticated encryption scheme (used in legacy packer).
type CryptoBox interface {
	Easy(payload, nonce, theirPub []byte, myKID string) ([]byte, error)
	EasyOpen(cipherText, nonce, theirPub, myPub []byte) ([]byte, error)
	SealOpen(cipherText, myPub []byte) ([]byte, error)
}

// Provider contains dependencies for the KMS service.
type Provider interface {
	KeystoreService() keystore.Service
	KeyManager() kms.KeyManager
	Crypto() crypto.Crypto
	CryptoBox() CryptoBox
}

type service struct {
	keystore   keystore.Service
	keyManager kms.KeyManager
	crypto     crypto.Crypto
	cryptoBox  CryptoBox
}

// NewService returns a new Service instance.
func NewService(provider Provider) Service {
	return &service{
		keystore:   provider.KeystoreService(),
		keyManager: provider.KeyManager(),
		crypto:     provider.Crypto(),
		cryptoBox:  provider.CryptoBox(),
	}
}

// CreateKey creates a new key and associates it with Keystore.
func (s *service) CreateKey(keystoreID string, kt kms.KeyType) (string, error) {
	keyID, _, err := s.keyManager.Create(kt)
	if err != nil {
		return "", NewServiceError(createKeyFailed, err)
	}

	k, err := s.keystore.Get(keystoreID)
	if err != nil {
		return "", NewServiceError(getKeystoreFailed, err)
	}

	k.KeyIDs = append(k.KeyIDs, keyID)

	err = s.keystore.Save(k)
	if err != nil {
		return "", NewServiceError(saveKeystoreFailed, err)
	}

	return keyID, nil
}

// ExportKey exports a public key.
func (s *service) ExportKey(keystoreID, keyID string) ([]byte, error) {
	if err := s.checkKey(keystoreID, keyID); err != nil {
		return nil, err
	}

	b, err := s.keyManager.ExportPubKeyBytes(keyID)
	if err != nil {
		return nil, NewServiceError(exportKeyFailed, err)
	}

	return b, nil
}

// Sign signs a message.
func (s *service) Sign(keystoreID, keyID string, msg []byte) ([]byte, error) {
	kh, err := s.getKeyHandle(keystoreID, keyID)
	if err != nil {
		return nil, err
	}

	sig, err := s.crypto.Sign(msg, kh)
	if err != nil {
		return nil, NewServiceError(signMessageFailed, err)
	}

	return sig, nil
}

// Verify verifies a signature for the message.
func (s *service) Verify(keystoreID, keyID string, sig, msg []byte) error {
	kh, err := s.getKeyHandle(keystoreID, keyID)
	if err != nil {
		return err
	}

	pub, err := kh.(*keyset.Handle).Public()
	if err != nil {
		return NewServiceError(noPublicKeyFailure, err)
	}

	err = s.crypto.Verify(sig, msg, pub)
	if err != nil {
		return NewServiceError(verifySignatureFailed, err)
	}

	return nil
}

// Encrypt encrypts a message with additional authenticated data (AAD).
func (s *service) Encrypt(keystoreID, keyID string, msg, aad []byte) ([]byte, []byte, error) {
	kh, err := s.getKeyHandle(keystoreID, keyID)
	if err != nil {
		return nil, nil, err
	}

	cipher, nonce, err := s.crypto.Encrypt(msg, aad, kh)
	if err != nil {
		return nil, nil, NewServiceError(encryptMessageFailed, err)
	}

	return cipher, nonce, nil
}

// Decrypt decrypts a cipher with AAD and a nonce.
func (s *service) Decrypt(keystoreID, keyID string, cipher, aad, nonce []byte) ([]byte, error) {
	kh, err := s.getKeyHandle(keystoreID, keyID)
	if err != nil {
		return nil, err
	}

	plain, err := s.crypto.Decrypt(cipher, aad, nonce, kh)
	if err != nil {
		return nil, NewServiceError(decryptCipherFailed, err)
	}

	return plain, nil
}

// ComputeMAC computes message authentication code (MAC) for data.
func (s *service) ComputeMAC(keystoreID, keyID string, data []byte) ([]byte, error) {
	kh, err := s.getKeyHandle(keystoreID, keyID)
	if err != nil {
		return nil, err
	}

	mac, err := s.crypto.ComputeMAC(data, kh)
	if err != nil {
		return nil, NewServiceError(computeMACFailed, err)
	}

	return mac, nil
}

// VerifyMAC determines if the given mac is a correct message authentication code (MAC) for data.
func (s *service) VerifyMAC(keystoreID, keyID string, mac, data []byte) error {
	kh, err := s.getKeyHandle(keystoreID, keyID)
	if err != nil {
		return err
	}

	err = s.crypto.VerifyMAC(mac, data, kh)
	if err != nil {
		return NewServiceError(verifyMACFailed, err)
	}

	return nil
}

// WrapKey wraps cek for the recipient with public key 'recipientPubKey'.
func (s *service) WrapKey(keystoreID, keyID string, cek, apu, apv []byte,
	recipientPubKey *crypto.PublicKey) (*crypto.RecipientWrappedKey, error) {
	if keyID != "" {
		kh, err := s.getKeyHandle(keystoreID, keyID)
		if err != nil {
			return nil, err
		}

		// ECDH-1PU key wrapping (Authcrypt)
		recipientWrappedKey, err := s.crypto.WrapKey(cek, apu, apv, recipientPubKey, crypto.WithSender(kh))
		if err != nil {
			return nil, NewServiceError(wrapKeyFailed, err)
		}

		return recipientWrappedKey, nil
	}

	recipientWrappedKey, err := s.crypto.WrapKey(cek, apu, apv, recipientPubKey)
	if err != nil {
		return nil, NewServiceError(wrapKeyFailed, err)
	}

	return recipientWrappedKey, nil
}

// UnwrapKey unwraps a key in recipientWK.
func (s *service) UnwrapKey(keystoreID, keyID string, recipientWK *crypto.RecipientWrappedKey,
	senderPubKey *crypto.PublicKey) ([]byte, error) {
	kh, err := s.getKeyHandle(keystoreID, keyID)
	if err != nil {
		return nil, err
	}

	if senderPubKey != nil {
		senderKH, e := keyio.PublicKeyToKeysetHandle(senderPubKey)
		if e != nil {
			return nil, NewServiceError(unwrapKeyFailed, e)
		}

		// ECDH-1PU key unwrapping (Authcrypt)
		cek, e := s.crypto.UnwrapKey(recipientWK, kh, crypto.WithSender(senderKH))
		if e != nil {
			return nil, NewServiceError(unwrapKeyFailed, e)
		}

		return cek, nil
	}

	cek, err := s.crypto.UnwrapKey(recipientWK, kh)
	if err != nil {
		return nil, NewServiceError(unwrapKeyFailed, err)
	}

	return cek, nil
}

func (s *service) getKeyHandle(keystoreID, keyID string) (interface{}, error) {
	if err := s.checkKey(keystoreID, keyID); err != nil {
		return nil, err
	}

	kh, err := s.keyManager.Get(keyID)
	if err != nil {
		return nil, NewServiceError(getKeyFailed, err)
	}

	return kh, nil
}

func (s *service) checkKey(keystoreID, keyID string) error {
	k, err := s.keystore.Get(keystoreID)
	if err != nil {
		return NewServiceError(getKeystoreFailed, err)
	}

	if len(k.KeyIDs) == 0 {
		return NewServiceError(noKeysFailure, nil)
	}

	found := false

	for _, id := range k.KeyIDs {
		if id == keyID {
			found = true

			break
		}
	}

	if !found {
		return NewServiceError(invalidKeyFailure, nil)
	}

	return nil
}
