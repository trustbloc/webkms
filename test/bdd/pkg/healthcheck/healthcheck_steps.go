/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package healthcheck

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/cucumber/godog"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/hub-kms/test/bdd/pkg/context"
	"github.com/trustbloc/hub-kms/test/bdd/pkg/internal/bddutil"
)

const (
	contentType = "application/json"
)

// Steps defines steps for health check.
type Steps struct {
	bddContext *context.BDDContext
	response   []byte
	logger     log.Logger
}

// NewSteps creates steps for health check.
func NewSteps() *Steps {
	return &Steps{logger: log.New("kms-rest/tests/healthcheck")}
}

// RegisterSteps registers agent steps.
func (s *Steps) RegisterSteps(ctx *godog.ScenarioContext) {
	ctx.Step(`^HTTP GET is sent to "([^"]*)"$`, s.httpGet)
	ctx.Step(`^the status field in the response has the value "([^"]*)"$`, s.validateResponse)
}

// SetContext is called before every scenario is run with a fresh new context.
func (s *Steps) SetContext(ctx *context.BDDContext) {
	s.bddContext = ctx
}

func (s *Steps) httpGet(url string) error {
	resp, err := bddutil.HTTPDo(http.MethodGet, url, headers(), nil, s.bddContext.TLSConfig())
	if err != nil {
		return err
	}

	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			s.logger.Warnf("Error closing HTTP response from [%s]: %s", url, errClose)
		}
	}()

	s.response, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response body failed: %s", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("received status code %d", resp.StatusCode)
	}

	return nil
}

func (s *Steps) validateResponse(expected string) error {
	var healthCheckResp struct {
		Status string `json:"status"`
	}

	if err := json.Unmarshal(s.response, &healthCheckResp); err != nil {
		return err
	}

	if healthCheckResp.Status != expected {
		return fmt.Errorf("expected status 'success', got: %s", healthCheckResp.Status)
	}

	return nil
}

func headers() map[string]string {
	return map[string]string{
		"Content-Type": contentType,
	}
}
