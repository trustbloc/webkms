/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"fmt"
	"net/http"

	"github.com/cucumber/godog"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/hub-kms/test/bdd/pkg/bddutil"
	"github.com/trustbloc/hub-kms/test/bdd/pkg/context"
)

const (
	serverEndpoint = "https://%s:%d"
)

// Steps defines context for BDD test steps.
type Steps struct {
	bddContext *context.BDDContext
	logger     log.Logger
}

// NewSteps creates a new Steps.
func NewSteps() *Steps {
	return &Steps{logger: log.New("kms-rest/tests/common")}
}

// SetContext sets a fresh context for every scenario.
func (s *Steps) SetContext(ctx *context.BDDContext) {
	s.bddContext = ctx
}

// RegisterSteps defines scenario steps.
func (s *Steps) RegisterSteps(ctx *godog.ScenarioContext) {
	ctx.Step(`^Key Server is running on "([^"]*)" port "([^"]*)"$`, s.checkServerIsRun)
}

func (s *Steps) checkServerIsRun(host string, port int) error {
	url := fmt.Sprintf(serverEndpoint+"/healthcheck", host, port)

	resp, err := bddutil.HTTPDo(http.MethodGet, url, "", nil, s.bddContext.TLSConfig())
	if err != nil {
		return err
	}

	err = resp.Body.Close()
	if err != nil {
		s.logger.Errorf("Failed to close response body: %s", err)
	}

	s.bddContext.ServerEndpoint = fmt.Sprintf(serverEndpoint, host, port)

	return nil
}
