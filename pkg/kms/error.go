/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import "errors"

const (
	createKeyFailed       = "create key failed"
	getKeystoreFailed     = "get keystore failed"
	getKeyFailed          = "get key failed"
	saveKeystoreFailed    = "save keystore failed"
	signMessageFailed     = "sign message failed"
	verifySignatureFailed = "verify signature failed"
	encryptMessageFailed  = "encrypt message failed"
	decryptCipherFailed   = "decrypt cipher failed"
	computeMACFailed      = "compute MAC failed"
	verifyMACFailed       = "verify MAC failed"

	noPublicKeyFailure = "no public key"
	noKeysFailure      = "no keys defined"
	invalidKeyFailure  = "invalid key"
)

type serviceError struct {
	msg string
	err error
}

func (e *serviceError) Error() string {
	if e.err != nil {
		return e.msg + ": " + e.err.Error()
	}

	return e.msg
}

func (e *serviceError) Unwrap() error {
	return e.err
}

// ErrorMessage returns the user-friendly error message.
func ErrorMessage(err error) string {
	var e *serviceError
	if errors.As(err, &e) && e.msg != "" {
		return e.msg
	}

	return err.Error()
}
