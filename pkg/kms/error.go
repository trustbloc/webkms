/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import "errors"

const (
	createKeyFailed       = "create key failed"
	exportKeyFailed       = "export public key failed"
	getKeystoreFailed     = "get keystore failed"
	getKeyFailed          = "get key failed"
	saveKeystoreFailed    = "save keystore failed"
	signMessageFailed     = "sign message failed"
	verifySignatureFailed = "verify signature failed"
	encryptMessageFailed  = "encrypt message failed"
	decryptCipherFailed   = "decrypt cipher failed"
	computeMACFailed      = "compute MAC failed"
	verifyMACFailed       = "verify MAC failed"
	wrapKeyFailed         = "key wrapping failed"
	unwrapKeyFailed       = "key unwrapping failed"

	noPublicKeyFailure = "no public key"
	noKeysFailure      = "no keys defined"
	invalidKeyFailure  = "invalid key"

	easyMessageFailed     = "easy message failed"
	easyOpenMessageFailed = "easy open message failed"
	sealOpenPayloadFailed = "seal open payload failed"
)

// ServiceError represents a KMS service error.
type ServiceError struct {
	msg string
	err error
}

// NewServiceError returns a new instance of ServiceError.
func NewServiceError(msg string, err error) ServiceError {
	return ServiceError{msg: msg, err: err}
}

func (e ServiceError) Error() string {
	if e.err != nil {
		return e.msg + ": " + e.err.Error()
	}

	return e.msg
}

// Unwrap gets the underlying error of ServiceError.
func (e ServiceError) Unwrap() error {
	return e.err
}

// UserErrorMessage returns the user-friendly error message.
func UserErrorMessage(err error) string {
	var e ServiceError
	if errors.As(err, &e) && e.msg != "" {
		return e.msg
	}

	return err.Error()
}
