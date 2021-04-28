/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package keystore

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/cucumber/godog"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/zcapld"
	authbddctx "github.com/trustbloc/hub-auth/test/bdd/pkg/context"
	authlogin "github.com/trustbloc/hub-auth/test/bdd/pkg/login"

	"github.com/trustbloc/kms/test/bdd/pkg/context"
	"github.com/trustbloc/kms/test/bdd/pkg/internal/bddutil"
)

const (
	controller = "did:example:123456789"

	createKeystoreReq = `{
	  "controller": "` + controller + `"
	}`

	contentType = "application/json"
)

// Steps defines steps context for keystore operations.
type Steps struct {
	bddContext     *context.BDDContext
	status         string
	headers        http.Header
	logger         log.Logger
	authBDDContext *authbddctx.BDDContext
}

// NewSteps creates a new Steps.
func NewSteps(authBDDContext *authbddctx.BDDContext) *Steps {
	return &Steps{
		authBDDContext: authBDDContext,
		logger:         log.New("kms-rest/tests/keystore"),
	}
}

// SetContext sets a fresh context for every scenario.
func (s *Steps) SetContext(ctx *context.BDDContext) {
	s.bddContext = ctx
}

// RegisterSteps defines scenario steps.
func (s *Steps) RegisterSteps(ctx *godog.ScenarioContext) {
	ctx.Step(`^user makes an HTTP POST to "([^"]*)" to create a keystore$`, s.sendCreateKeystoreRequest)
	ctx.Step(`^user gets a response with HTTP status "([^"]*)" and with valid "([^"]*)" and "([^"]*)" headers$`,
		s.checkResponse)
}

func (s *Steps) sendCreateKeystoreRequest(endpoint string) error {
	login := authlogin.NewSteps(s.authBDDContext)

	if _, err := login.NewWalletLogin(); err != nil {
		return fmt.Errorf("failed to login wallet: %w", err)
	}

	body := bytes.NewBuffer([]byte(createKeystoreReq))

	resp, err := bddutil.HTTPDo(
		http.MethodPost,
		endpoint,
		headers(s.authBDDContext.AccessToken()),
		body, s.bddContext.TLSConfig(),
	)
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
	s.headers = resp.Header

	return nil
}

func (s *Steps) checkResponse(status, locationHeader, capabilityHeader string) error {
	if s.status != status {
		return fmt.Errorf("expected HTTP response status %q, got: %q", status, s.status)
	}

	_, err := url.ParseRequestURI(s.headers.Get(locationHeader))
	if err != nil {
		return fmt.Errorf("expected %q header to be a valid URL, got error: %w", locationHeader, err)
	}

	encoded := s.headers.Get(capabilityHeader)
	if encoded == "" {
		return fmt.Errorf("header '%s' not found in response", capabilityHeader)
	}

	decoded, err := base64.URLEncoding.DecodeString(encoded)
	if err != nil {
		return fmt.Errorf("failed to base64-decode capability header: %w", err)
	}

	compressed, err := gzip.NewReader(bytes.NewReader(decoded))
	if err != nil {
		return fmt.Errorf("failed to open new gzip reader: %w", err)
	}

	uncompressed, err := ioutil.ReadAll(compressed)
	if err != nil {
		return fmt.Errorf("failed to gunzip capability: %w", err)
	}

	zcap, err := zcapld.ParseCapability(uncompressed)
	if err != nil {
		return fmt.Errorf("failed to parse capability: %w", err)
	}

	if zcap.Invoker != controller {
		return fmt.Errorf(
			"service returned wrong invoker; expected %s got %s",
			controller, zcap.Invoker,
		)
	}

	return nil
}

func headers(token string) map[string]string {
	return map[string]string{
		"Content-Type":  contentType,
		"Authorization": fmt.Sprintf("Bearer %s", token),
	}
}
