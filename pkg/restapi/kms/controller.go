/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"github.com/trustbloc/hub-kms/pkg/restapi/kms/operation"
)

// Controller defines a controller for KMS operations.
type Controller struct {
	handlers []operation.Handler
}

// New returns a new Controller instance.
func New(provider operation.Provider) *Controller {
	op := operation.New(provider)
	handlers := op.GetRESTHandlers()

	return &Controller{handlers: handlers}
}

// GetOperations returns supported HTTP handlers for KMS operations.
func (c *Controller) GetOperations() []operation.Handler {
	return c.handlers
}
