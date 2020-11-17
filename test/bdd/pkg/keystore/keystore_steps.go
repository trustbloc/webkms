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
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/hub-kms/test/bdd/pkg/bddutil"
	"github.com/trustbloc/hub-kms/test/bdd/pkg/context"
)

const (
	createKeystoreReq = `{
	  "controller": "did:example:123456789"
	}`

	contentType = "application/json"
)

// Steps defines steps context for keystore operations.
type Steps struct {
	bddContext *context.BDDContext
	status     string
	headers    map[string]string
	logger     log.Logger
}

// NewSteps creates a new Steps.
func NewSteps() *Steps {
	return &Steps{logger: log.New("kms-rest/tests/keystore")}
}

// SetContext sets a fresh context for every scenario.
func (s *Steps) SetContext(ctx *context.BDDContext) {
	s.bddContext = ctx
}

// RegisterSteps defines scenario steps.
func (s *Steps) RegisterSteps(ctx *godog.ScenarioContext) {
	ctx.Step(`^user makes an HTTP POST to "([^"]*)" to create a keystore$`, s.sendCreateKeystoreRequest)
	ctx.Step(`^user gets a response with HTTP status "([^"]*)" and "([^"]*)" header with a valid URL$`,
		s.checkResponse)
}

func (s *Steps) sendCreateKeystoreRequest(endpoint string) error {
	body := bytes.NewBuffer([]byte(createKeystoreReq))

	resp, err := bddutil.HTTPDo(http.MethodPost, endpoint, headers(), body, s.bddContext.TLSConfig())
	if err != nil {
		return err
	}

	defer func() {
		err := resp.Body.Close()
		if err != nil {
			s.logger.Errorf("Failed to close response body: %s", err.Error())
		}
	}()

	s.status = resp.Status

	h := make(map[string]string, len(resp.Header))
	for k, v := range resp.Header {
		h[k] = v[0]
	}

	s.headers = h

	return nil
}

func (s *Steps) checkResponse(status, header string) error {
	if s.status != status {
		return fmt.Errorf("expected HTTP response status %q, got: %q", status, s.status)
	}

	_, err := url.ParseRequestURI(s.headers[header])
	if err != nil {
		return fmt.Errorf("expected %q header to be a valid URL, got error: %q", header, err)
	}

	return nil
}

func headers() map[string]string {
	return map[string]string{
		"Content-Type": contentType,
	}
}
