/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/cucumber/godog"

	"github.com/trustbloc/hub-kms/test/bdd/pkg/context"
)

const (
	createKeystoreReq = `{
	  "controller": "did:example:123456789"
	}`

	createKeyReq = `{
	  "keystoreID": "%s",
	  "keyType": "%s",
	  "passphrase": "p@ssphrase"
	}`

	createKeystoreEndpoint = "{serverEndpoint}/kms/keystores"

	contentType    = "application/json"
	locationHeader = "Location"
)

// Steps defines steps context for the KMS operations.
type Steps struct {
	bddContext       *context.BDDContext
	keystoreEndpoint string
	responseStatus   int
	responseLocation string
}

// NewSteps creates steps context for the KMS operations.
func NewSteps() *Steps {
	return &Steps{}
}

// SetContext sets a fresh context for every scenario.
func (s *Steps) SetContext(ctx *context.BDDContext) {
	s.bddContext = ctx
}

// RegisterSteps defines scenario steps.
func (s *Steps) RegisterSteps(gs *godog.Suite) {
	gs.Step(`^User has created a keystore on the server$`, s.createKeystore)
	gs.Step(`^User sends an HTTP POST to "([^"]*)" to create a key of "([^"]*)" type$`, s.sendCreateKeyReq)
	gs.Step("^User gets a response with HTTP 201 Created and "+
		"Location with a valid URL for the newly created key$", s.checkResponse)
}

func (s *Steps) createKeystore() error {
	postURL := strings.ReplaceAll(createKeystoreEndpoint, "{serverEndpoint}", s.bddContext.ServerEndpoint)

	resp, err := http.Post(postURL, contentType, bytes.NewBuffer([]byte(createKeystoreReq)))
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	s.keystoreEndpoint = resp.Header.Get(locationHeader)

	return nil
}

func (s *Steps) sendCreateKeyReq(endpoint, keyType string) error {
	keystoreID := path.Base(s.keystoreEndpoint)
	req := fmt.Sprintf(createKeyReq, keystoreID, keyType)

	postURL := strings.ReplaceAll(endpoint, "{keystoreEndpoint}", s.keystoreEndpoint)

	resp, err := http.Post(postURL, contentType, bytes.NewBuffer([]byte(req)))
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
