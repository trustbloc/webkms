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

	"github.com/trustbloc/hub-kms/test/bdd/pkg/context"
	"github.com/trustbloc/hub-kms/test/bdd/pkg/internal/bddutil"
)

const (
	serverEndpoint = "https://%s:%d"
	contentType    = "application/json"
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
	ctx.Step(`^Key Server is running on "([^"]*)" port "([^"]*)"$`, s.checkKeyServerIsRun)
	ctx.Step(`^AuthZ Key Server is running on "([^"]*)" port "([^"]*)"$`, s.checkAuthzKeyServerIsRun)
	ctx.Step(`^EDV is running on "([^"]*)" port "([^"]*)"$`, s.checkEDVServerIsRun)
	ctx.Step(`^Hub Auth is running on "([^"]*)" port "([^"]*)"$`, s.checkHubAuthIsRun)
}

func (s *Steps) checkKeyServerIsRun(host string, port int) error {
	url, err := s.healthCheck(host, port)
	if err != nil {
		return err
	}

	s.bddContext.KeyServerURL = url

	return nil
}

func (s *Steps) checkAuthzKeyServerIsRun(host string, port int) error {
	url, err := s.healthCheck(host, port)
	if err != nil {
		return err
	}

	s.bddContext.AuthZKeyServerURL = url

	return nil
}

func (s *Steps) checkEDVServerIsRun(host string, port int) error {
	url, err := s.healthCheck(host, port)
	if err != nil {
		return err
	}

	s.bddContext.EDVServerURL = url

	return nil
}

func (s *Steps) checkHubAuthIsRun(host string, port int) error {
	url, err := s.healthCheck(host, port)
	if err != nil {
		return err
	}

	s.bddContext.HubAuthURL = url

	return nil
}

func (s *Steps) healthCheck(host string, port int) (string, error) {
	url := fmt.Sprintf(serverEndpoint+"/healthcheck", host, port)

	resp, err := bddutil.HTTPDo(http.MethodGet, url, headers(), nil, s.bddContext.TLSConfig())
	if err != nil {
		return "", err
	}

	err = resp.Body.Close()
	if err != nil {
		s.logger.Errorf("Failed to close response body: %s", err)
	}

	return fmt.Sprintf(serverEndpoint, host, port), nil
}

func headers() map[string]string {
	return map[string]string{
		"Content-Type": contentType,
	}
}
