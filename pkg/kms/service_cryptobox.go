/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

// Easy seals a message with a provided nonce.
func (s *service) Easy(keystoreID, keyID string, payload, nonce, theirPub []byte) ([]byte, error) {
	if err := s.checkKey(keystoreID, keyID); err != nil {
		return nil, err
	}

	cipher, err := s.cryptoBox.Easy(payload, nonce, theirPub, keyID)
	if err != nil {
		return nil, NewServiceError(easyMessageFailed, err)
	}

	return cipher, nil
}

// EasyOpen unseals a message sealed with Easy, where the nonce is provided.
func (s *service) EasyOpen(keystoreID string, cipherText, nonce, theirPub, myPub []byte) ([]byte, error) {
	if _, err := s.keystore.Get(keystoreID); err != nil {
		return nil, NewServiceError(getKeystoreFailed, err)
	}

	plain, err := s.cryptoBox.EasyOpen(cipherText, nonce, theirPub, myPub)
	if err != nil {
		return nil, NewServiceError(easyOpenMessageFailed, err)
	}

	return plain, nil
}

// SealOpen decrypts a payload encrypted with Seal.
func (s *service) SealOpen(keystoreID string, cipher, myPub []byte) ([]byte, error) {
	if _, err := s.keystore.Get(keystoreID); err != nil {
		return nil, NewServiceError(getKeystoreFailed, err)
	}

	plain, err := s.cryptoBox.SealOpen(cipher, myPub)
	if err != nil {
		return nil, NewServiceError(sealOpenPayloadFailed, err)
	}

	return plain, nil
}
