/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package restapi

import (
	"github.com/trustbloc/hub-kms/pkg/keystore"
	"github.com/trustbloc/hub-kms/pkg/restapi/operation"
)

// Controller contains handlers for controller.
type Controller struct {
	handlers []operation.Handler
}

// New returns a new controller instance.
func New(provider keystore.Provider) *Controller {
	op := operation.New(provider)
	handlers := op.GetRESTHandlers()

	return &Controller{handlers: handlers}
}

// GetOperations returns all controller endpoints.
func (c *Controller) GetOperations() []operation.Handler {
	return c.handlers
}
