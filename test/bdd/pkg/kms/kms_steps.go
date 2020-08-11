/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/cucumber/godog"

	"github.com/trustbloc/hub-kms/test/bdd/pkg/bddutil"
	"github.com/trustbloc/hub-kms/test/bdd/pkg/context"
)

const (
	createKeystoreReq = `{
	  "controller": "did:example:123456789"
	}`

	createKeyReq = `{
	  "keyType": "%s",
	  "passphrase": "p@ssphrase"
	}`

	signMessageReq = `{
	  "message": "%s",
	  "passphrase": "p@ssphrase"
	}`

	verifySignatureReq = `{
	  "signature": "%s",
	  "message": "%s",
	  "passphrase": "p@ssphrase"
	}`

	createKeystoreEndpoint = "{serverEndpoint}/kms/keystores"
	keysEndpoint           = "https://{keystoreEndpoint}/keys"

	contentType    = "application/json"
	locationHeader = "Location"
)

// Steps defines steps context for the KMS operations.
type Steps struct {
	bddContext       *context.BDDContext
	keystoreEndpoint string
	message          string
	signature        string
	responseStatus   int
	responseLocation string
	responseBody     []byte
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
	// create key steps
	gs.Step(`^User has created an empty keystore on the server$`, s.createKeystore)
	gs.Step(`^User sends an HTTP POST to "([^"]*)" to create a key of "([^"]*)" type$`, s.sendCreateKeyReq)
	gs.Step("^User gets a response with HTTP 201 Created and "+
		"Location with a valid URL for the newly created key$", s.checkCreateKeyResp)
	// sign message steps
	gs.Step(`^User has created a keystore with a key of "([^"]*)" type on the server$`, s.createKeystoreAndKey)
	gs.Step(`^User sends an HTTP POST to "([^"]*)" to sign a message "([^"]*)"$`, s.sendSignMessageReq)
	gs.Step(`^User gets a response with HTTP 200 OK and a signature in the body$`, s.checkSignMessageResp)
	// verify signature steps
	gs.Step(`^User sends an HTTP POST to "([^"]*)" to verify a signature from the body$`, s.sendVerifySignatureReq)
	gs.Step(`^User gets a response with HTTP 200 OK and no error in the body$`, s.checkVerifySignatureResp)
}

func (s *Steps) createKeystore() error {
	postURL := strings.ReplaceAll(createKeystoreEndpoint, "{serverEndpoint}", s.bddContext.ServerEndpoint)

	body := bytes.NewBuffer([]byte(createKeystoreReq))
	resp, err := bddutil.HTTPDo(http.MethodPost, postURL, contentType, body, s.bddContext.TLSConfig())
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	s.keystoreEndpoint = resp.Header.Get(locationHeader)

	return nil
}

func (s *Steps) sendCreateKeyReq(endpoint, keyType string) error {
	postURL := strings.ReplaceAll(endpoint, "{keystoreEndpoint}", s.keystoreEndpoint)

	req := fmt.Sprintf(createKeyReq, keyType)
	body := bytes.NewBuffer([]byte(req))

	resp, err := bddutil.HTTPDo(http.MethodPost, postURL, contentType, body, s.bddContext.TLSConfig())
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	s.responseStatus = resp.StatusCode
	s.responseLocation = resp.Header.Get(locationHeader)

	return nil
}

func (s *Steps) checkCreateKeyResp() error {
	if s.responseStatus != http.StatusCreated {
		return fmt.Errorf("expected HTTP 201 Created, got: %d", s.responseStatus)
	}

	_, err := url.ParseRequestURI(s.responseLocation)
	if err != nil {
		return fmt.Errorf("expected Location to be a valid URL, got: %s", err)
	}

	return nil
}

func (s *Steps) createKeystoreAndKey(keyType string) error {
	err := s.createKeystore()
	if err != nil {
		return err
	}

	err = s.sendCreateKeyReq(keysEndpoint, keyType)
	if err != nil {
		return err
	}

	return nil
}

func (s *Steps) sendSignMessageReq(endpoint, message string) error {
	postURL := strings.ReplaceAll(endpoint, "{keyEndpoint}", s.responseLocation)

	req := fmt.Sprintf(signMessageReq, message)
	body := bytes.NewBuffer([]byte(req))

	resp, err := bddutil.HTTPDo(http.MethodPost, postURL, contentType, body, s.bddContext.TLSConfig())
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	s.responseStatus = resp.StatusCode

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	s.responseBody = respBody

	s.message = message
	s.signature = string(respBody)

	return nil
}

func (s *Steps) checkSignMessageResp() error {
	if s.responseStatus != http.StatusOK {
		return fmt.Errorf("expected HTTP 200 OK, got: %d", s.responseStatus)
	}

	if len(s.responseBody) == 0 {
		return errors.New("expected non-empty response body")
	}

	return nil
}

func (s *Steps) sendVerifySignatureReq(endpoint string) error {
	postURL := strings.ReplaceAll(endpoint, "{keyEndpoint}", s.responseLocation)

	req := fmt.Sprintf(verifySignatureReq, s.signature, s.message)
	body := bytes.NewBuffer([]byte(req))

	resp, err := bddutil.HTTPDo(http.MethodPost, postURL, contentType, body, s.bddContext.TLSConfig())
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	s.responseStatus = resp.StatusCode

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	s.responseBody = respBody

	return nil
}

func (s *Steps) checkVerifySignatureResp() error {
	if s.responseStatus != http.StatusOK {
		return fmt.Errorf("expected HTTP 200 OK, got: %d", s.responseStatus)
	}

	if len(s.responseBody) != 0 {
		return fmt.Errorf("expected no error in the body, got: %q", string(s.responseBody))
	}

	return nil
}
