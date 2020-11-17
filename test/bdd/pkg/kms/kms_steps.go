/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/cucumber/godog"
	"github.com/rs/xid"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edv/pkg/client"
	"github.com/trustbloc/edv/pkg/restapi/models"

	"github.com/trustbloc/hub-kms/test/bdd/pkg/bddutil"
	"github.com/trustbloc/hub-kms/test/bdd/pkg/context"
)

const (
	createKeystoreReq = `{
	  "controller": "%s",
	  "operationalVaultID": "%s"
	}`

	createKeyReq = `{
	  "keyType": "%s"
	}`

	signMessageReq = `{
	  "message": "%s"
	}`

	verifySignatureReq = `{
	  "signature": "%s",
	  "message": "%s"
	}`

	encryptMessageReq = `{
	  "message": "%s",
	  "aad": "%s"
	}`

	decryptCipherReq = `{
	  "cipherText": "%s",
	  "aad": "%s",
	  "nonce": "%s"
	}`

	computeMACReq = `{
	  "data": "%s"
	}`

	verifyMACReq = `{
	  "mac": "%s",
	  "data": "%s"
	}`

	edvBasePath            = "/encrypted-data-vaults"
	createKeystoreEndpoint = "/kms/keystores"
	keysEndpoint           = "/kms/keystores/{keystoreID}/keys"

	contentType = "application/json"
	passphrase  = "p@ssphrase"
)

const (
	testController = "did:example:123456789"
	testAAD        = "additional data"
)

// Steps defines steps context for the KMS operations.
type Steps struct {
	bddContext         *context.BDDContext
	logger             log.Logger
	operationalVaultID string
	urlParams          map[string]string
	status             string
	headers            map[string]string
	response           map[string]string
}

// NewSteps creates steps context for the KMS operations.
func NewSteps() *Steps {
	return &Steps{
		logger:    log.New("kms-rest/tests/kms"),
		urlParams: make(map[string]string, 2), // keystoreID and keyID
	}
}

// SetContext sets a fresh context for every scenario.
func (s *Steps) SetContext(ctx *context.BDDContext) {
	s.bddContext = ctx
}

// RegisterSteps defines scenario steps.
func (s *Steps) RegisterSteps(ctx *godog.ScenarioContext) {
	// common creation steps
	ctx.Step(`^user has created a data vault on SDS Server for storing operational keys$`, s.createEDVDataVault)
	ctx.Step(`^user has created an empty keystore on Key Server$`, s.createKeystore)
	ctx.Step(`^user has created a keystore with "([^"]*)" key on Key Server$`, s.createKeystoreAndKey)
	// common response checking steps
	ctx.Step(`^user gets a response with HTTP status "([^"]*)"$`, s.checkResponseStatus)
	ctx.Step(`^user gets a response with "([^"]*)" header with a valid URL$`, s.checkHeaderWithValidURL)
	ctx.Step(`^user gets a response with non-empty "([^"]*)"$`, s.checkResponseWithNonEmptyValue)
	ctx.Step(`^user gets a response with no "([^"]*)"$`, s.checkResponseWithNoValue)
	ctx.Step(`^user gets a response with "([^"]*)" with value "([^"]*)"$`, s.checkResponseWithValue)
	// create/export key steps
	ctx.Step(`^user makes an HTTP POST to "([^"]*)" to create "([^"]*)" key$`, s.sendCreateKeyRequest)
	ctx.Step(`^user makes an HTTP GET to "([^"]*)" to export public key$`, s.sendExportPubKeyRequest)
	// sign/verify message steps
	ctx.Step(`^user makes an HTTP POST to "([^"]*)" to sign "([^"]*)"$`, s.sendSignMessageRequest)
	ctx.Step(`^user makes an HTTP POST to "([^"]*)" to verify "([^"]*)" for "([^"]*)"$`, s.sendVerifySignatureRequest)
	// encrypt/decrypt message steps
	ctx.Step(`^user makes an HTTP POST to "([^"]*)" to encrypt "([^"]*)"$`, s.sendEncryptMessageRequest)
	ctx.Step(`^user makes an HTTP POST to "([^"]*)" to decrypt "([^"]*)"$`, s.sendDecryptCipherRequest)
	// compute/verify MAC steps
	ctx.Step(`^user makes an HTTP POST to "([^"]*)" to compute MAC for "([^"]*)"$`, s.sendComputeMACRequest)
	ctx.Step(`^user makes an HTTP POST to "([^"]*)" to verify MAC "([^"]*)" for "([^"]*)"$`, s.sendVerifyMACRequest)
}

func (s *Steps) createEDVDataVault() error {
	config := models.DataVaultConfiguration{
		Sequence:    0,
		Controller:  testController,
		ReferenceID: xid.New().String(),
		KEK:         models.IDTypePair{ID: "https://example.com/kms/12345", Type: "AesKeyWrappingKey2019"},
		HMAC:        models.IDTypePair{ID: "https://example.com/kms/67891", Type: "Sha256HmacKey2019"},
	}

	c := client.New(s.bddContext.SDSServerURL+edvBasePath, client.WithTLSConfig(s.bddContext.TLSConfig()))

	vaultLocation, err := c.CreateDataVault(&config)
	if err != nil {
		return err
	}

	parts := strings.Split(vaultLocation, "/")
	s.operationalVaultID = parts[len(parts)-1]

	return nil
}

func (s *Steps) createKeystore() error {
	req := fmt.Sprintf(createKeystoreReq, testController, s.operationalVaultID)

	resp, closeBody, err := s.post(s.bddContext.KeyServerURL+createKeystoreEndpoint, req)
	if err != nil {
		return err
	}

	defer closeBody()

	return s.processResponse(resp)
}

func (s *Steps) createKeystoreAndKey(keyType string) error {
	err := s.createKeystore()
	if err != nil {
		return err
	}

	return s.sendCreateKeyRequest(s.bddContext.KeyServerURL+keysEndpoint, keyType)
}

func (s *Steps) sendCreateKeyRequest(endpoint, keyType string) error {
	req := fmt.Sprintf(createKeyReq, keyType)

	resp, closeBody, err := s.post(endpoint, req)
	if err != nil {
		return err
	}

	defer closeBody()

	return s.processResponse(resp)
}

func (s *Steps) sendExportPubKeyRequest(endpoint string) error {
	resp, closeBody, err := s.get(endpoint)
	if err != nil {
		return err
	}

	defer closeBody()

	return s.processResponse(resp)
}

func (s *Steps) sendSignMessageRequest(endpoint, message string) error {
	req := fmt.Sprintf(signMessageReq, message)

	resp, closeBody, err := s.post(endpoint, req)
	if err != nil {
		return err
	}

	defer closeBody()

	return s.processResponse(resp)
}

func (s *Steps) sendVerifySignatureRequest(endpoint, prop, message string) error {
	req := fmt.Sprintf(verifySignatureReq, s.response[prop], message)

	resp, closeBody, err := s.post(endpoint, req)
	if err != nil {
		return err
	}

	defer closeBody()

	return s.processResponse(resp)
}

func (s *Steps) sendEncryptMessageRequest(endpoint, message string) error {
	req := fmt.Sprintf(encryptMessageReq, message, testAAD)

	resp, closeBody, err := s.post(endpoint, req)
	if err != nil {
		return err
	}

	defer closeBody()

	return s.processResponse(resp)
}

func (s *Steps) sendDecryptCipherRequest(endpoint, prop string) error {
	req := fmt.Sprintf(decryptCipherReq, s.response[prop], testAAD, s.response["nonce"])

	resp, closeBody, err := s.post(endpoint, req)
	if err != nil {
		return err
	}

	defer closeBody()

	return s.processResponse(resp)
}

func (s *Steps) sendComputeMACRequest(endpoint, data string) error {
	req := fmt.Sprintf(computeMACReq, data)

	resp, closeBody, err := s.post(endpoint, req)
	if err != nil {
		return err
	}

	defer closeBody()

	return s.processResponse(resp)
}

func (s *Steps) sendVerifyMACRequest(endpoint, prop, data string) error {
	req := fmt.Sprintf(verifyMACReq, s.response[prop], data)

	resp, closeBody, err := s.post(endpoint, req)
	if err != nil {
		return err
	}

	defer closeBody()

	return s.processResponse(resp)
}

func (s *Steps) checkResponseStatus(status string) error {
	if s.status != status {
		return fmt.Errorf("expected HTTP response status %q, got: %q", status, s.status)
	}

	return nil
}

func (s *Steps) checkHeaderWithValidURL(header string) error {
	_, err := url.ParseRequestURI(s.headers[header])
	if err != nil {
		return fmt.Errorf("expected %q header to be a valid URL, got error: %q", header, err)
	}

	return nil
}

func (s *Steps) checkResponseWithNonEmptyValue(prop string) error {
	if s.response[prop] == "" {
		return fmt.Errorf("expected property %q to be non-empty", prop)
	}

	return nil
}

func (s *Steps) checkResponseWithNoValue(prop string) error {
	v, ok := s.response[prop]
	if ok {
		return fmt.Errorf("expected no property %q, got with value: %q", prop, v)
	}

	return nil
}

func (s *Steps) checkResponseWithValue(prop, val string) error {
	if s.response[prop] != val {
		return fmt.Errorf("expected %q to be %q, got: %q", prop, val, s.response[prop])
	}

	return nil
}

func buildURL(endpoint string, params map[string]string) string {
	pairs := make([]string, 2*len(params)) //nolint:gomnd // double size to include old-new pairs for replacer

	i := 0

	for k, v := range params {
		pairs[i] = fmt.Sprintf("{%s}", k)
		pairs[i+1] = v
		i += 2
	}

	return strings.NewReplacer(pairs...).Replace(endpoint)
}

func headers() map[string]string {
	return map[string]string{
		"Content-Type":   contentType,
		"Hub-Kms-Secret": passphrase,
	}
}

//nolint:interfacer // `log.Logger` communicates the meaning better than the suggested `assert.TestingT` interface
func closeBodyFunc(closer io.Closer, logger log.Logger) func() {
	return func() {
		err := closer.Close()
		if err != nil {
			logger.Errorf("Failed to close response body: %s", err.Error())
		}
	}
}

func (s *Steps) get(endpoint string) (*http.Response, func(), error) {
	getURL := buildURL(endpoint, s.urlParams)

	resp, err := bddutil.HTTPDo(http.MethodGet, getURL, headers(), nil, s.bddContext.TLSConfig())
	if err != nil {
		return nil, nil, err
	}

	return resp, closeBodyFunc(resp.Body, s.logger), nil
}

func (s *Steps) post(endpoint, body string) (*http.Response, func(), error) {
	postURL := buildURL(endpoint, s.urlParams)
	buf := bytes.NewBuffer([]byte(body))

	resp, err := bddutil.HTTPDo(http.MethodPost, postURL, headers(), buf, s.bddContext.TLSConfig())
	if err != nil {
		return nil, nil, err
	}

	return resp, closeBodyFunc(resp.Body, s.logger), nil
}

func (s *Steps) processResponse(resp *http.Response) error {
	s.status = resp.Status

	s.processResponseHeaders(resp)

	return s.processResponseValues(resp)
}

func (s *Steps) processResponseHeaders(resp *http.Response) {
	location := resp.Header.Get("Location")
	if location != "" {
		s.setURLParams(location)
	}

	h := make(map[string]string, len(resp.Header))
	for k, v := range resp.Header {
		h[k] = v[0]
	}

	s.headers = h
}

func (s *Steps) setURLParams(location string) {
	keystoreID, keyID := parseLocation(location)

	if keystoreID != "" {
		s.urlParams["keystoreID"] = keystoreID
	}

	if keyID != "" {
		s.urlParams["keyID"] = keyID
	}
}

func parseLocation(loc string) (string, string) {
	const (
		keystoreIDPos = 3 // localhost:8076/kms/keystores/{keystoreID}
		keyIDPos      = 5 // localhost:8076/kms/keystores/{keystoreID}/keys/{keyID}
	)

	s := strings.Split(loc, "/")

	keystoreID := ""
	if len(s) > keystoreIDPos {
		keystoreID = s[keystoreIDPos]
	}

	keyID := ""
	if len(s) > keyIDPos {
		keyID = s[keyIDPos]
	}

	return keystoreID, keyID
}

func (s *Steps) processResponseValues(resp *http.Response) error {
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil
	}

	var jsonResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&jsonResp); err != nil && !errors.Is(err, io.EOF) {
		return err
	}

	m := make(map[string]string)

	for k, v := range jsonResp {
		a, ok := v.(string)
		if ok {
			m[k] = a
		}
	}

	s.response = m

	return nil
}
