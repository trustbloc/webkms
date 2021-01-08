/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"fmt"

	"github.com/google/tink/go/keyset"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
)

// Sign signs a message.
func (s *service) Sign(msg []byte, kh interface{}) ([]byte, error) {
	signature, err := s.crypto.Sign(msg, kh)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	return signature, nil
}

// Verify verifies a signature for the message.
func (s *service) Verify(signature, msg []byte, kh interface{}) error {
	pub, err := kh.(*keyset.Handle).Public()
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}

	err = s.crypto.Verify(signature, msg, pub)
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}

	return nil
}

// Encrypt encrypts a message with additional authenticated data (AAD).
func (s *service) Encrypt(msg, aad []byte, kh interface{}) ([]byte, []byte, error) {
	cipher, nonce, err := s.crypto.Encrypt(msg, aad, kh)
	if err != nil {
		return nil, nil, fmt.Errorf("encrypt: %w", err)
	}

	return cipher, nonce, nil
}

// Decrypt decrypts a cipher with AAD and a nonce.
func (s *service) Decrypt(cipher, aad, nonce []byte, kh interface{}) ([]byte, error) {
	plain, err := s.crypto.Decrypt(cipher, aad, nonce, kh)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return plain, nil
}

// ComputeMAC computes message authentication code (MAC) for data.
func (s *service) ComputeMAC(data []byte, kh interface{}) ([]byte, error) {
	mac, err := s.crypto.ComputeMAC(data, kh)
	if err != nil {
		return nil, fmt.Errorf("compute MAC: %w", err)
	}

	return mac, nil
}

// VerifyMAC determines if the given mac is a correct message authentication code (MAC) for data.
func (s *service) VerifyMAC(mac, data []byte, kh interface{}) error {
	err := s.crypto.VerifyMAC(mac, data, kh)
	if err != nil {
		return fmt.Errorf("verify MAC: %w", err)
	}

	return nil
}

// WrapKey wraps CEK for the recipient with public key 'recPubKey'.
func (s *service) WrapKey(cek, apu, apv []byte, recPubKey *crypto.PublicKey, opts ...crypto.WrapKeyOpts) (
	*crypto.RecipientWrappedKey, error) {
	recWK, err := s.crypto.WrapKey(cek, apu, apv, recPubKey, opts...)
	if err != nil {
		return nil, fmt.Errorf("wrap key: %w", err)
	}

	return recWK, nil
}

// UnwrapKey unwraps a key in recWK.
func (s *service) UnwrapKey(recWK *crypto.RecipientWrappedKey, kh interface{}, opts ...crypto.WrapKeyOpts) (
	[]byte, error) {
	cek, err := s.crypto.UnwrapKey(recWK, kh, opts...)
	if err != nil {
		return nil, fmt.Errorf("unwrap key: %w", err)
	}

	return cek, nil
}
