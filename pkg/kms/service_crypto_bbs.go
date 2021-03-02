/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"fmt"

	"github.com/google/tink/go/keyset"
)

func (s *service) SignMulti(messages [][]byte, kh interface{}) ([]byte, error) {
	signature, err := s.crypto.SignMulti(messages, kh)
	if err != nil {
		return nil, fmt.Errorf("sign multi: %w", err)
	}

	return signature, nil
}

func (s *service) VerifyMulti(messages [][]byte, signature []byte, kh interface{}) error {
	pub, err := kh.(*keyset.Handle).Public()
	if err != nil {
		return fmt.Errorf("verify multi: %w", err)
	}

	err = s.crypto.VerifyMulti(messages, signature, pub)
	if err != nil {
		return fmt.Errorf("verify multi: %w", err)
	}

	return nil
}

func (s *service) DeriveProof(messages [][]byte, bbsSignature, nonce []byte, revealedIndexes []int,
	kh interface{}) ([]byte, error) {
	pub, err := kh.(*keyset.Handle).Public()
	if err != nil {
		return nil, fmt.Errorf("derive proof: %w", err)
	}

	proof, err := s.crypto.DeriveProof(messages, bbsSignature, nonce, revealedIndexes, pub)
	if err != nil {
		return nil, fmt.Errorf("derive proof: %w", err)
	}

	return proof, nil
}

func (s *service) VerifyProof(revealedMessages [][]byte, proof, nonce []byte, kh interface{}) error {
	pub, err := kh.(*keyset.Handle).Public()
	if err != nil {
		return fmt.Errorf("verify proof: %w", err)
	}

	err = s.crypto.VerifyProof(revealedMessages, proof, nonce, pub)
	if err != nil {
		return fmt.Errorf("verify proof: %w", err)
	}

	return nil
}
