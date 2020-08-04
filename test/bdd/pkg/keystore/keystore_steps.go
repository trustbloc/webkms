/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package keystore

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"

	"github.com/cucumber/godog"

	"github.com/trustbloc/hub-kms/test/bdd/pkg/bddutil"
	"github.com/trustbloc/hub-kms/test/bdd/pkg/context"
)

const (
	createKeystoreReq = `{
	  "controller": "did:example:123456789"
	}`

	contentType    = "application/json"
	locationHeader = "Location"
)

// Steps defines steps context for keystore operations.
type Steps struct {
	bddContext       *context.BDDContext
	responseStatus   int
	responseLocation string
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
	gs.Step(`^User sends an HTTP POST to "([^"]*)" to create a keystore$`, s.sendCreateKeystoreReq)
	gs.Step("^User gets a response with HTTP 201 Created and "+
		"Location with a valid URL for the newly created keystore$", s.checkResponse)
}

func (s *Steps) sendCreateKeystoreReq(endpoint string) error {
	body := bytes.NewBuffer([]byte(createKeystoreReq))
	resp, err := bddutil.HTTPDo(http.MethodPost, endpoint, contentType, body, s.bddContext.TLSConfig())
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
