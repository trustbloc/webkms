/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package healthcheck

import "github.com/trustbloc/hub-kms/pkg/restapi/healthcheck/operation"

// Controller contains handlers for controller.
type Controller struct {
	handlers []operation.Handler
}

// New returns new controller instance.
func New() *Controller {
	op := operation.New()

	return &Controller{
		handlers: op.GetRESTHandlers(),
	}
}

// GetOperations returns all controller endpoints.
func (c *Controller) GetOperations() []operation.Handler {
	return c.handlers
}
