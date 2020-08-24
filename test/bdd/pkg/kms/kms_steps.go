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

	encryptMessageReq = `{
	  "message": "%s",
	  "aad": "%s",
	  "passphrase": "p@ssphrase"
	}`

	decryptCipherReq = `{
	  "cipherText": "%s",
	  "aad": "%s",
	  "nonce": "%s",
	  "passphrase": "p@ssphrase"
	}`

	computeMACReq = `{
	  "data": "%s",
	  "passphrase": "p@ssphrase"
	}`

	verifyMACReq = `{
	  "mac": "%s",
	  "data": "%s",
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
	cipherText       string
	nonce            string
	plainText        string
	data             string
	mac              string
	errorMessage     string
	responseStatus   int
	responseLocation string
	responseError    string
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
	// common steps
	gs.Step(`^User has created a keystore with a key of "([^"]*)" type on the server$`, s.createKeystoreAndKey)
	gs.Step(`^User gets a response with HTTP 200 OK and no error in the body$`, s.checkSuccessfulResp)
	// create key steps
	gs.Step(`^User has created an empty keystore on the server$`, s.createKeystore)
	gs.Step(`^User sends an HTTP POST to "([^"]*)" to create a key of "([^"]*)" type$`, s.sendCreateKeyReq)
	gs.Step("^User gets a response with HTTP 201 Created and "+
		"Location with a valid URL for the newly created key$", s.checkCreateKeyResp)
	// sign message steps
	gs.Step(`^User sends an HTTP POST to "([^"]*)" to sign a message "([^"]*)"$`, s.sendSignMessageReq)
	gs.Step(`^User gets a response with HTTP 200 OK and a signature in the JSON body$`, s.checkSignMessageResp)
	// verify signature steps
	gs.Step(`^User sends an HTTP POST to "([^"]*)" to verify a signature from the body$`, s.sendVerifySignatureReq)
	// encrypt message steps
	gs.Step(`^User sends an HTTP POST to "([^"]*)" to encrypt a message "([^"]*)"$`, s.sendEncryptMessageReq)
	gs.Step(`^User gets a response with HTTP 200 OK and a cipher text in the JSON body$`, s.checkEncryptMessageResp)
	// decrypt cipher steps
	gs.Step(`^User sends an HTTP POST to "([^"]*)" to decrypt a cipher text from the body$`, s.sendDecryptCipherReq)
	gs.Step(`^User gets a response with HTTP 200 OK and a plain text "([^"]*)" in the JSON body$`, s.checkDecryptCipherResp)
	// compute MAC steps
	gs.Step(`^User sends an HTTP POST to "([^"]*)" to compute MAC for data "([^"]*)"$`, s.sendComputeMACReq)
	gs.Step(`^User gets a response with HTTP 200 OK and MAC in the JSON body$`, s.checkComputeMACResp)
	// verify MAC steps
	gs.Step(`^User sends an HTTP POST to "([^"]*)" to verify MAC for data$`, s.sendVerifyMACReq)
}

func (s *Steps) checkSuccessfulResp() error {
	if s.responseStatus != http.StatusOK {
		return fmt.Errorf("expected HTTP 200 OK, got: %d", s.responseStatus)
	}

	if len(s.errorMessage) != 0 {
		return fmt.Errorf("expected no error in the body, got: %s", s.errorMessage)
	}

	return nil
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

	err = s.checkCreateKeyResp()
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

	s.message = message
	s.responseStatus = resp.StatusCode

	var signResp struct {
		Signature string `json:"signature"`
	}
	if err = json.NewDecoder(resp.Body).Decode(&signResp); err != nil {
		return err
	}

	s.signature = signResp.Signature

	return nil
}

func (s *Steps) checkSignMessageResp() error {
	if s.responseStatus != http.StatusOK {
		return fmt.Errorf("expected HTTP 200 OK, got: %d", s.responseStatus)
	}

	if len(s.signature) == 0 {
		return errors.New("expected non-empty signature")
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

	errMsg, err := readErrorMessage(resp.Body)
	if err != nil {
		return err
	}
	s.errorMessage = errMsg

	return nil
}

func (s *Steps) sendEncryptMessageReq(endpoint, message string) error {
	postURL := strings.ReplaceAll(endpoint, "{keyEndpoint}", s.responseLocation)

	req := fmt.Sprintf(encryptMessageReq, message, "additional data")
	body := bytes.NewBuffer([]byte(req))

	resp, err := bddutil.HTTPDo(http.MethodPost, postURL, contentType, body, s.bddContext.TLSConfig())
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	s.responseStatus = resp.StatusCode

	var encryptResp struct {
		CipherText string `json:"cipherText"`
		Nonce      string `json:"nonce"`
	}
	if err = json.NewDecoder(resp.Body).Decode(&encryptResp); err != nil {
		return err
	}

	s.cipherText = encryptResp.CipherText
	s.nonce = encryptResp.Nonce

	return nil
}

func (s *Steps) checkEncryptMessageResp() error {
	if s.responseStatus != http.StatusOK {
		return fmt.Errorf("expected HTTP 200 OK, got: %d", s.responseStatus)
	}

	if len(s.cipherText) == 0 {
		return errors.New("expected non-empty cipher text")
	}

	return nil
}

func (s *Steps) sendDecryptCipherReq(endpoint string) error {
	postURL := strings.ReplaceAll(endpoint, "{keyEndpoint}", s.responseLocation)

	req := fmt.Sprintf(decryptCipherReq, s.cipherText, "additional data", s.nonce)
	body := bytes.NewBuffer([]byte(req))

	resp, err := bddutil.HTTPDo(http.MethodPost, postURL, contentType, body, s.bddContext.TLSConfig())
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	s.responseStatus = resp.StatusCode

	var decryptResp struct {
		PlainText string `json:"plainText"`
	}
	if err = json.NewDecoder(resp.Body).Decode(&decryptResp); err != nil {
		return err
	}

	s.plainText = decryptResp.PlainText

	return nil
}

func (s *Steps) checkDecryptCipherResp(expectedPlainText string) error {
	if s.responseStatus != http.StatusOK {
		return fmt.Errorf("expected HTTP 200 OK, got: %d", s.responseStatus)
	}

	if s.plainText != expectedPlainText {
		return fmt.Errorf("expected plain text to be: %s, got: %s", expectedPlainText, s.plainText)
	}

	return nil
}

func (s *Steps) sendComputeMACReq(endpoint, data string) error {
	postURL := strings.ReplaceAll(endpoint, "{keyEndpoint}", s.responseLocation)

	req := fmt.Sprintf(computeMACReq, data)
	body := bytes.NewBuffer([]byte(req))

	resp, err := bddutil.HTTPDo(http.MethodPost, postURL, contentType, body, s.bddContext.TLSConfig())
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	s.data = data
	s.responseStatus = resp.StatusCode

	var computeMACResp struct {
		MAC string `json:"mac"`
	}
	if err = json.NewDecoder(resp.Body).Decode(&computeMACResp); err != nil {
		return err
	}

	s.mac = computeMACResp.MAC

	return nil
}

func (s *Steps) checkComputeMACResp() error {
	if s.responseStatus != http.StatusOK {
		return fmt.Errorf("expected HTTP 200 OK, got: %d", s.responseStatus)
	}

	if len(s.mac) == 0 {
		return errors.New("expected non-empty MAC")
	}

	return nil
}

func (s *Steps) sendVerifyMACReq(endpoint string) error {
	postURL := strings.ReplaceAll(endpoint, "{keyEndpoint}", s.responseLocation)

	req := fmt.Sprintf(verifyMACReq, s.mac, s.data)
	body := bytes.NewBuffer([]byte(req))

	resp, err := bddutil.HTTPDo(http.MethodPost, postURL, contentType, body, s.bddContext.TLSConfig())
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	s.responseStatus = resp.StatusCode

	errMsg, err := readErrorMessage(resp.Body)
	if err != nil {
		return err
	}
	s.errorMessage = errMsg

	return nil
}

func readErrorMessage(r io.Reader) (string, error) {
	respBody, err := ioutil.ReadAll(r)
	if err != nil {
		return "", err
	}

	if len(respBody) > 0 {
		var errorResp struct {
			ErrorMessage string `json:"errMsg,omitempty"`
		}
		if err = json.Unmarshal(respBody, &errorResp); err != nil {
			return "", err
		}

		return errorResp.ErrorMessage, nil
	}

	return "", nil
}
