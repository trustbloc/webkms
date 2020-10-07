/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/trustbloc/edge-core/pkg/log"

	support "github.com/trustbloc/hub-kms/pkg/internal/common"
)

const (
	healthCheckEndpoint = "/healthcheck"
)

// Handler http handler for each controller API endpoint.
type Handler interface {
	Path() string
	Method() string
	Handle() http.HandlerFunc
}

// Operation defines handlers for healthcheck operations.
type Operation struct {
	logger log.Logger
}

// New returns a new Operation instance.
func New(logger log.Logger) *Operation {
	return &Operation{logger: logger}
}

// GetRESTHandlers gets controller API handlers available for healthcheck service.
func (o *Operation) GetRESTHandlers() []Handler {
	return []Handler{
		support.NewHTTPHandler(healthCheckEndpoint, http.MethodGet, o.healthCheckHandler),
	}
}

func (o *Operation) healthCheckHandler(rw http.ResponseWriter, _ *http.Request) {
	rw.WriteHeader(http.StatusOK)

	err := json.NewEncoder(rw).Encode(&healthCheckResp{
		Status:      "success",
		CurrentTime: time.Now(),
	})
	if err != nil {
		o.logger.Errorf("healthcheck response failure: %s", err)
	}
}
