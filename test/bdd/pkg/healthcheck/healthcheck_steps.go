/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package healthcheck

import (
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/cucumber/godog"
	"github.com/pkg/errors"
	logger "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"

	"github.com/trustbloc/hub-kms/test/bdd/pkg/context"
)

// Steps defines steps for health check
type Steps struct {
	bddContext *context.BDDContext
	queryValue string
}

// NewSteps creates steps for health check
func NewSteps() *Steps {
	return &Steps{}
}

// RegisterSteps registers agent steps
func (s *Steps) RegisterSteps(gs *godog.Suite) {
	gs.Step(`^HTTP GET is sent to "([^"]*)"$`, s.httpGet)
	gs.Step(`^The "([^"]*)" field in the response has the value "([^"]*)"$`, s.validateJSONResField)
}

// SetContext is called before every scenario is run with a fresh new context
func (s *Steps) SetContext(ctx *context.BDDContext) {
	s.bddContext = ctx
}

// httpGet sends a GET request to the given URL.
func (s *Steps) httpGet(url string) error {
	s.queryValue = ""

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: s.bddContext.TLSConfig()}}
	defer client.CloseIdleConnections()

	httpReq, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		return err
	}

	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			logger.Warnf("Error closing HTTP response from [%s]: %s", url, errClose)
		}
	}()

	payload, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response body failed: %s", err)
	}

	s.queryValue = string(payload)

	if resp.StatusCode != http.StatusOK {
		return errors.Errorf("received status code %d", resp.StatusCode)
	}

	return nil
}

func (s *Steps) validateJSONResField(path, expected string) error {
	r := gjson.Get(s.queryValue, path)

	logger.Debugf("Path [%s] of JSON %s resolves to %s", path, s.queryValue, r.Str)

	if r.Str == expected {
		return nil
	}

	return fmt.Errorf("JSON path resolves to [%s] which is not the expected value [%s]", r.Str, expected)
}
