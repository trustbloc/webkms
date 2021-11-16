/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package keystore

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
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
	response       []byte
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
	ctx.Step(`^user gets a response with HTTP status "([^"]*)" and valid key store URL and root capabilities$`,
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

	respBody, er := io.ReadAll(resp.Body)
	if er != nil {
		return fmt.Errorf("read response body: %w", er)
	}

	s.response = respBody

	return nil
}

func (s *Steps) checkResponse(status string) error {
	if s.status != status {
		return fmt.Errorf("expected HTTP response status %q, got: %q", status, s.status)
	}

	var resp struct {
		KeyStoreURL string `json:"key_store_url"`
		Capability  []byte `json:"capability"`
	}

	if err := json.Unmarshal(s.response, &resp); err != nil {
		return fmt.Errorf("%s", err)
	}

	_, err := url.ParseRequestURI(resp.KeyStoreURL)
	if err != nil {
		return fmt.Errorf("invalid key store URL: %w", err)
	}

	decoded, err := base64.URLEncoding.DecodeString(string(resp.Capability))
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
