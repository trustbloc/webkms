/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kmsoperations

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"

	"github.com/cucumber/godog"
	logger "github.com/sirupsen/logrus"

	"github.com/trustbloc/hub-kms/test/bdd/pkg/context"
)

const (
	validConfiguration = `{
	  "sequence": 0,
	  "controller": "did:example:123456789"
	}`

	contentType    = "application/json"
	locationHeader = "Location"
)

// Steps defines steps context for KMS operations
type Steps struct {
	bddContext       *context.BDDContext
	responseStatus   int
	responseLocation string
}

// NewSteps creates steps context for KMS operations
func NewSteps() *Steps {
	return &Steps{}
}

// SetContext sets a fresh context for every scenario
func (s *Steps) SetContext(ctx *context.BDDContext) {
	s.bddContext = ctx
}

// RegisterSteps defines scenario steps
func (s *Steps) RegisterSteps(gs *godog.Suite) {
	gs.Step(`^Key Server is running on "([^"]*)" port "([^"]*)"$`, s.checkServerIsRun)
	gs.Step(`^User sends an HTTP POST to "([^"]*)" with a valid configuration$`, s.sendRequest)
	gs.Step(`^User gets a response with HTTP 201 Created and Location with a valid URL for the newly created keystore$`, s.checkResponse) //nolint:lll
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

	return nil
}

func (s *Steps) sendRequest(endpoint string) error {
	resp, err := http.Post(endpoint, contentType, bytes.NewBuffer([]byte(validConfiguration)))
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	s.responseStatus = resp.StatusCode
	s.responseLocation = resp.Header.Get(locationHeader)

	return nil
}

func (s *Steps) checkResponse() error {
	if s.responseStatus != http.StatusCreated {
		return fmt.Errorf("expected HTTP 201 Created, got: %d", s.responseStatus)
	}

	_, err := url.ParseRequestURI(s.responseLocation)
	if err != nil {
		return fmt.Errorf("expected Location to be a valid URL, got: %s", err)
	}

	return nil
}
