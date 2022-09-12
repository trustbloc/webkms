/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"fmt"
	"net/http"
	"os"

	"github.com/cucumber/godog"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/kms/test/bdd/pkg/auth"
	"github.com/trustbloc/kms/test/bdd/pkg/context"
	"github.com/trustbloc/kms/test/bdd/pkg/internal/bddutil"
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
	return &Steps{logger: log.New("kms/tests/common")}
}

// SetContext sets a fresh context for every scenario.
func (s *Steps) SetContext(ctx *context.BDDContext) {
	s.bddContext = ctx
}

// RegisterSteps defines scenario steps.
func (s *Steps) RegisterSteps(ctx *godog.ScenarioContext) {
	ctx.Step(`^Key Server is running on "([^"]*)" port "([^"]*)"$`, s.checkKeyServerIsRun)
	ctx.Step(`^Hub Auth is running on "([^"]*)" port "([^"]*)"$`, s.checkHubAuthIsRun)

	ctx.Step(`^Key Server is running on "([^"]*)" env$`, s.checkKeyServerIsRunEnv)
	ctx.Step(`^Hub Auth is running on "([^"]*)" env$`, s.checkHubAuthIsRunEnv)
}

func (s *Steps) checkKeyServerIsRun(host string, port int) error {
	url, err := s.healthCheck(host, port)
	if err != nil {
		return err
	}

	s.bddContext.KeyServerURL = url

	return nil
}

func (s *Steps) checkHubAuthIsRun(host string, port int) error {
	url, err := s.healthCheck(host, port)
	if err != nil {
		return err
	}

	s.bddContext.HubAuthURL = url
	s.bddContext.LoginConfig = auth.CreateDefaultConfig(url)

	return nil
}

func (s *Steps) checkKeyServerIsRunEnv(serverURLEnv string) error {
	url, err := getServerURL(serverURLEnv)
	if err != nil {
		return err
	}

	err = s.healthCheckURL(url)
	if err != nil {
		return err
	}

	s.bddContext.KeyServerURL = url

	return nil
}

func (s *Steps) checkHubAuthIsRunEnv(serverURLEnv string) error {
	url, err := getServerURL(serverURLEnv)
	if err != nil {
		return err
	}

	err = s.healthCheckURL(url)
	if err != nil {
		return err
	}

	s.bddContext.HubAuthURL = url

	return nil
}

func (s *Steps) healthCheck(host string, port int) (string, error) {
	url := fmt.Sprintf(serverEndpoint, host, port)

	if err := s.healthCheckURL(url); err != nil {
		return "", err
	}

	return url, nil
}

func (s *Steps) healthCheckURL(url string) error {
	resp, err := bddutil.HTTPDo(http.MethodGet, url+"/healthcheck", headers(), nil, s.bddContext.TLSConfig())
	if err != nil {
		return err
	}

	err = resp.Body.Close()
	if err != nil {
		s.logger.Errorf("Failed to close response body: %s", err)
	}

	return nil
}

func headers() map[string]string {
	return map[string]string{
		"Content-Type": contentType,
	}
}

func getServerURL(serverURLEnv string) (string, error) {
	keyServerURL := os.Getenv(serverURLEnv)
	if keyServerURL == "" {
		return "", fmt.Errorf("env varialble %s not set", serverURLEnv)
	}

	return keyServerURL, nil
}
