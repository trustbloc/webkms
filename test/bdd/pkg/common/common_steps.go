/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"fmt"
	"net/http"

	"github.com/cucumber/godog"
	logger "github.com/sirupsen/logrus"

	"github.com/trustbloc/hub-kms/test/bdd/pkg/context"
)

const (
	serverEndpoint = "http://%s:%d"
)

// Steps defines context for BDD test steps.
type Steps struct {
	bddContext *context.BDDContext
}

// NewSteps creates a new Steps.
func NewSteps() *Steps {
	return &Steps{}
}

// SetContext sets a fresh context for every scenario.
func (s *Steps) SetContext(ctx *context.BDDContext) {
	s.bddContext = ctx
}

// RegisterSteps defines scenario steps.
func (s *Steps) RegisterSteps(gs *godog.Suite) {
	gs.Step(`^Key Server is running on "([^"]*)" port "([^"]*)"$`, s.checkServerIsRun)
}

func (s *Steps) checkServerIsRun(host string, port int) error {
	resp, err := http.Get(fmt.Sprintf("http://%s:%d/healthcheck", host, port))
	if err != nil {
		return err
	}

	err = resp.Body.Close()
	if err != nil {
		logger.Errorf("Failed to close response body: %s", err)
	}

	s.bddContext.ServerEndpoint = fmt.Sprintf(serverEndpoint, host, port)

	return nil
}
