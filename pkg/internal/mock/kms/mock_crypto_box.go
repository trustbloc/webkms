/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

// MockCryptoBox is a mock CryptoBox.
type MockCryptoBox struct {
	EasyValue     []byte
	EasyOpenValue []byte
	SealOpenValue []byte
	EasyErr       error
	EasyOpenErr   error
	SealOpenErr   error
}

// Easy seals a message with a provided nonce.
func (m *MockCryptoBox) Easy(payload, nonce, theirPub []byte, myKID string) ([]byte, error) {
	if m.EasyErr != nil {
		return nil, m.EasyErr
	}

	return m.EasyValue, nil
}

// EasyOpen unseals a message sealed with Easy, where the nonce is provided.
func (m *MockCryptoBox) EasyOpen(cipherText, nonce, theirPub, myPub []byte) ([]byte, error) {
	if m.EasyOpenErr != nil {
		return nil, m.EasyOpenErr
	}

	return m.EasyOpenValue, nil
}

// SealOpen decrypts a payload encrypted with Seal.
func (m *MockCryptoBox) SealOpen(cipherText, myPub []byte) ([]byte, error) {
	if m.SealOpenErr != nil {
		return nil, m.SealOpenErr
	}

	return m.SealOpenValue, nil
}
