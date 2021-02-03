/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package healthcheck

import (
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/kms/pkg/restapi/healthcheck/operation"
)

// Controller contains handlers for controller.
type Controller struct {
	handlers []operation.Handler
}

// New returns new controller instance.
func New(logger log.Logger) *Controller {
	op := operation.New(logger)

	return &Controller{
		handlers: op.GetRESTHandlers(),
	}
}

// GetOperations returns all controller endpoints.
func (c *Controller) GetOperations() []operation.Handler {
	return c.handlers
}
