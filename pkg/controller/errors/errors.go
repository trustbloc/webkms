/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package errors

import (
	"errors"
	"net/http"
)

// Service errors.
var (
	ErrValidation = NewBadRequestError(New("validation failed"))
	ErrBadRequest = NewBadRequestError(New("bad request"))
	ErrNotFound   = NewNotFoundError(New("not found"))
	ErrInternal   = NewStatusInternalServerError(New("internal error"))
)

// StatusErr an error with status code.
type StatusErr struct {
	error
	status int
}

// Unwrap returns the result of calling the Unwrap method on err.
func (e *StatusErr) Unwrap() error {
	return errors.Unwrap(e.error)
}

// StatusCode returns HTTP status code.
func (e *StatusErr) StatusCode() int {
	return e.status
}

// New returns an error that formats as the given text.
func New(text string) error {
	return errors.New(text)
}

// NewStatusInternalServerError represents InternalServerError.
func NewStatusInternalServerError(err error) *StatusErr {
	return &StatusErr{error: err, status: http.StatusInternalServerError}
}

// NewBadRequestError represents BadRequest error.
func NewBadRequestError(err error) *StatusErr {
	return &StatusErr{error: err, status: http.StatusBadRequest}
}

// NewNotFoundError represents NotFound error.
func NewNotFoundError(err error) *StatusErr {
	return &StatusErr{error: err, status: http.StatusNotFound}
}

// StatusCodeFromError returns status code if an error implements an interface.
func StatusCodeFromError(e error) int {
	if err, ok := e.(interface{ StatusCode() int }); ok { // nolint: errorlint
		return err.StatusCode()
	}

	if err := errors.Unwrap(e); err != nil {
		return StatusCodeFromError(err)
	}

	return http.StatusInternalServerError
}
