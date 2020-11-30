/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/cucumber/godog"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/igor-pavlenko/httpsignatures-go"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/zcapld"
	authbddctx "github.com/trustbloc/hub-auth/test/bdd/pkg/context"

	zcapld2 "github.com/trustbloc/hub-kms/pkg/auth/zcapld"
	"github.com/trustbloc/hub-kms/pkg/restapi/kms/operation"
	"github.com/trustbloc/hub-kms/test/bdd/pkg/bddutil"
	"github.com/trustbloc/hub-kms/test/bdd/pkg/context"
)

const (
	createKeystoreEndpoint = "/kms/keystores"
	keysEndpoint           = "/kms/keystores/{keystoreID}/keys"
	exportKeyEndpoint      = "/kms/keystores/{keystoreID}/keys/{keyID}/export"
	signEndpoint           = "/kms/keystores/{keystoreID}/keys/{keyID}/sign"
	capabilityEndpoint     = "/kms/keystores/{keystoreID}/capability"
)

// Steps defines steps context for the KMS operations.
type Steps struct {
	bddContext     *context.BDDContext
	authBDDContext *authbddctx.BDDContext
	httpClient     *http.Client
	logger         log.Logger
	users          map[string]*user
	keys           map[string][]byte
}

// NewSteps creates steps context for the KMS operations.
func NewSteps(authBDDContext *authbddctx.BDDContext, tlsConfig *tls.Config) *Steps {
	return &Steps{
		authBDDContext: authBDDContext,
		httpClient:     &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}},
		logger:         log.New("kms-rest/tests/kms"),
		users:          map[string]*user{},
		keys:           map[string][]byte{"testCEK": bddutil.GenerateRandomBytes()},
	}
}

// SetContext sets a fresh context for every scenario.
func (s *Steps) SetContext(ctx *context.BDDContext) {
	s.bddContext = ctx
}

// RegisterSteps defines scenario steps.
func (s *Steps) RegisterSteps(ctx *godog.ScenarioContext) {
	// common creation steps
	ctx.Step(`^"([^"]*)" wallet has stored secret on Hub Auth$`, s.storeSecretInHubAuth)
	ctx.Step(`^"([^"]*)" has created a data vault on EDV for storing keys$`, s.createEDVDataVault)
	ctx.Step(`^"([^"]*)" has created an empty keystore on Key Server$`, s.createKeystore)
	ctx.Step(`^"([^"]*)" has created a keystore with "([^"]*)" key on Key Server$`, s.createKeystoreAndKey)
	// common response checking steps
	ctx.Step(`^"([^"]*)" gets a response with HTTP status "([^"]*)"$`, s.checkRespStatus)
	ctx.Step(`^"([^"]*)" gets a response with "([^"]*)" header with a valid URL$`, s.checkHeaderWithValidURL)
	ctx.Step(`^"([^"]*)" gets a response with non-empty "([^"]*)"$`, s.checkRespWithNonEmptyValue)
	ctx.Step(`^"([^"]*)" gets a response with no "([^"]*)"$`, s.checkRespWithNoValue)
	ctx.Step(`^"([^"]*)" gets a response with "([^"]*)" with value "([^"]*)"$`, s.checkRespWithValue)
	ctx.Step(`^"([^"]*)" gets a response with content of "([^"]*)" key$`, s.checkRespWithKeyContent)
	// create/export key steps
	ctx.Step(`^"([^"]*)" makes an HTTP POST to "([^"]*)" to create "([^"]*)" key$`, s.makeCreateKeyReq)
	ctx.Step(`^"([^"]*)" makes an HTTP GET to "([^"]*)" to export public key$`, s.makeExportPubKeyReq)
	// sign/verify message steps
	ctx.Step(`^"([^"]*)" makes an HTTP POST to "([^"]*)" to sign "([^"]*)"$`, s.makeSignMessageReq)
	ctx.Step(`^"([^"]*)" makes an HTTP POST to "([^"]*)" to verify "([^"]*)" for "([^"]*)"$`, s.makeVerifySignatureReq)
	// encrypt/decrypt message steps
	ctx.Step(`^"([^"]*)" makes an HTTP POST to "([^"]*)" to encrypt "([^"]*)"$`, s.makeEncryptMessageReq)
	ctx.Step(`^"([^"]*)" makes an HTTP POST to "([^"]*)" to decrypt "([^"]*)"$`, s.makeDecryptCipherReq)
	// compute/verify MAC steps
	ctx.Step(`^"([^"]*)" makes an HTTP POST to "([^"]*)" to compute MAC for "([^"]*)"$`, s.makeComputeMACReq)
	ctx.Step(`^"([^"]*)" makes an HTTP POST to "([^"]*)" to verify MAC "([^"]*)" for "([^"]*)"$`, s.makeVerifyMACReq)
	// wrap/unwrap key steps
	ctx.Step(`^"([^"]*)" has a public key of "([^"]*)"$`, s.getPubKeyOfRecipient)
	ctx.Step(`^"([^"]*)" makes an HTTP POST to "([^"]*)" to wrap "([^"]*)" for "([^"]*)"$`, s.makeWrapKeyReq)
	ctx.Step(`^"([^"]*)" makes an HTTP POST to "([^"]*)" to unwrap "([^"]*)" from "([^"]*)"$`, s.makeUnwrapKeyReq)
}

func (s *Steps) createKeystoreAndKey(user, keyType string) error {
	err := s.createKeystore(user)
	if err != nil {
		return err
	}

	return s.makeCreateKeyReq(user, s.bddContext.KeyServerURL+keysEndpoint, keyType)
}

func (s *Steps) createKeystore(userName string) error {
	u, ok := s.users[userName]
	if !ok {
		return fmt.Errorf("no user with name %s exist", userName)
	}

	r := &createKeystoreReq{
		Controller: u.controller,
		VaultID:    u.vaultID,
	}

	request, err := u.preparePostRequest(r, s.bddContext.KeyServerURL+createKeystoreEndpoint)
	if err != nil {
		return err
	}

	response, err := s.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("http do: %w", err)
	}

	defer func() {
		closeErr := response.Body.Close()
		if closeErr != nil {
			s.logger.Errorf("Failed to close response body: %s\n", closeErr.Error())
		}
	}()

	if err := u.processResponse(nil, response); err != nil {
		return err
	}

	return s.updateCapability(u)
}

func (s *Steps) updateCapability(u *user) error {
	// create chain capability
	chainCapability, err := s.createChainCapability(u)
	if err != nil {
		return err
	}

	chainCapabilityBytes, err := json.Marshal(chainCapability)
	if err != nil {
		return err
	}

	r := &operation.UpdateCapabilityReq{
		EDVCapability: chainCapabilityBytes,
	}

	request, err := u.preparePostRequest(r, s.bddContext.KeyServerURL+capabilityEndpoint)
	if err != nil {
		return err
	}

	err = u.SetCapabilityInvocation(request, actionStoreCapability)
	if err != nil {
		return fmt.Errorf("user failed to set capability: %w", err)
	}

	err = u.Sign(request)
	if err != nil {
		return fmt.Errorf("user failed to sign request: %w", err)
	}

	response, err := s.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("http do: %w", err)
	}

	defer func() {
		closeErr := response.Body.Close()
		if closeErr != nil {
			s.logger.Errorf("Failed to close response body: %s\n", closeErr.Error())
		}
	}()

	return u.processResponse(nil, response)
}

func (s *Steps) createChainCapability(u *user) (*zcapld.Capability, error) {
	return zcapld.NewCapability(
		&zcapld.Signer{
			SignatureSuite:     ed25519signature2018.New(suite.WithSigner(u.signer)),
			SuiteType:          ed25519signature2018.SignatureType,
			VerificationMethod: u.controller,
		},
		zcapld.WithParent(u.edvCapability.ID),
		zcapld.WithInvoker(u.response.headers[edvDIDKeyHeader]),
		zcapld.WithAllowedActions("read", "write"),
		zcapld.WithInvocationTarget(u.vaultID, edvResource),
		zcapld.WithCapabilityChain(u.edvCapability.Parent, u.edvCapability.ID))
}

func (s *Steps) makeCreateKeyReq(user, endpoint, keyType string) error {
	u, ok := s.users[user]
	if !ok {
		return fmt.Errorf("no user with name %s exist", user)
	}

	r := &createKeyReq{
		KeyType: keyType,
	}

	request, err := u.preparePostRequest(r, endpoint)
	if err != nil {
		return err
	}

	err = u.SetCapabilityInvocation(request, actionCreateKey)
	if err != nil {
		return fmt.Errorf("failed to set capability invocation: %w", err)
	}

	err = u.Sign(request)
	if err != nil {
		return fmt.Errorf("user failed to sign http message: %w", err)
	}

	response, err := s.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("http do: %w", err)
	}

	defer func() {
		closeErr := response.Body.Close()
		if closeErr != nil {
			s.logger.Errorf("Failed to close response body: %s\n", closeErr.Error())
		}
	}()

	respData, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("reading response body failed: %s", err)
	}

	s.logger.Errorf(string(respData))

	var data struct {
		Location string `json:"location"`
	}

	if err := json.Unmarshal(respData, &data); err != nil {
		return fmt.Errorf("keystore resp err : %w", err)
	}

	if data.Location == "" {
		return errors.New("location in resp body is nil")
	}

	return u.processResponse(nil, response)
}

func (s *Steps) makeExportPubKeyReq(userName, endpoint string) error {
	u := s.users[userName]

	request, err := u.prepareGetRequest(endpoint)
	if err != nil {
		return err
	}

	err = u.SetCapabilityInvocation(request, actionExportKey)
	if err != nil {
		return fmt.Errorf("user failed to set capability invocation: %w", err)
	}

	err = u.Sign(request)
	if err != nil {
		return fmt.Errorf("user failed to sign request: %w", err)
	}

	response, err := s.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("http do: %w", err)
	}

	defer func() {
		closeErr := response.Body.Close()
		if closeErr != nil {
			s.logger.Errorf("Failed to close response body: %s\n", closeErr.Error())
		}
	}()

	var exportKeyResponse exportKeyResp

	if respErr := u.processResponse(&exportKeyResponse, response); respErr != nil {
		return respErr
	}

	publicKey, err := base64.URLEncoding.DecodeString(exportKeyResponse.PublicKey)
	if err != nil {
		return err
	}

	u.response.body = map[string]string{
		"publicKey": string(publicKey),
	}

	return nil
}

func (s *Steps) makeSignMessageReq(userName, endpoint, message string) error {
	u, ok := s.users[userName]
	if !ok {
		return fmt.Errorf("no user with name %s exist", userName)
	}

	r := &signReq{
		Message: base64.URLEncoding.EncodeToString([]byte(message)),
	}

	request, err := u.preparePostRequest(r, endpoint)
	if err != nil {
		return err
	}

	err = u.SetCapabilityInvocation(request, actionSign)
	if err != nil {
		return fmt.Errorf("user failed to set zcap on request: %w", err)
	}

	err = u.Sign(request)
	if err != nil {
		return fmt.Errorf("user failed to sign request: %w", err)
	}

	response, err := s.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("http do: %w", err)
	}

	defer func() {
		closeErr := response.Body.Close()
		if closeErr != nil {
			s.logger.Errorf("Failed to close response body: %s\n", closeErr.Error())
		}
	}()

	var signResponse signResp

	if respErr := u.processResponse(&signResponse, response); respErr != nil {
		return respErr
	}

	signature, err := base64.URLEncoding.DecodeString(signResponse.Signature)
	if err != nil {
		return err
	}

	u.response.body = map[string]string{
		"signature": string(signature),
	}

	return nil
}

func (s *Steps) makeVerifySignatureReq(userName, endpoint, tag, message string) error {
	u := s.users[userName]

	r := &verifyReq{
		Signature: base64.URLEncoding.EncodeToString([]byte(u.response.body[tag])),
		Message:   base64.URLEncoding.EncodeToString([]byte(message)),
	}

	return s.makeVerifyReq(u, actionVerify, r, endpoint)
}

func (s *Steps) makeEncryptMessageReq(userName, endpoint, message string) error {
	u := s.users[userName]

	r := &encryptReq{
		Message:        base64.URLEncoding.EncodeToString([]byte(message)),
		AdditionalData: base64.URLEncoding.EncodeToString([]byte("additional data")),
	}

	request, err := u.preparePostRequest(r, endpoint)
	if err != nil {
		return err
	}

	err = u.SetCapabilityInvocation(request, actionEncrypt)
	if err != nil {
		return fmt.Errorf("user failed to set zcap on request: %w", err)
	}

	err = u.Sign(request)
	if err != nil {
		return fmt.Errorf("user failed to sign request: %w", err)
	}

	response, err := s.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("http do: %w", err)
	}

	defer func() {
		closeErr := response.Body.Close()
		if closeErr != nil {
			s.logger.Errorf("Failed to close response body: %s\n", closeErr.Error())
		}
	}()

	var encryptResponse encryptResp

	if respErr := u.processResponse(&encryptResponse, response); respErr != nil {
		return respErr
	}

	cipherText, err := base64.URLEncoding.DecodeString(encryptResponse.CipherText)
	if err != nil {
		return err
	}

	nonce, err := base64.URLEncoding.DecodeString(encryptResponse.Nonce)
	if err != nil {
		return err
	}

	u.response.body = map[string]string{
		"cipherText": string(cipherText),
		"nonce":      string(nonce),
	}

	return nil
}

func (s *Steps) makeDecryptCipherReq(userName, endpoint, tag string) error {
	u := s.users[userName]

	r := &decryptReq{
		CipherText:     base64.URLEncoding.EncodeToString([]byte(u.response.body[tag])),
		AdditionalData: base64.URLEncoding.EncodeToString([]byte("additional data")),
		Nonce:          base64.URLEncoding.EncodeToString([]byte(u.response.body["nonce"])),
	}

	request, err := u.preparePostRequest(r, endpoint)
	if err != nil {
		return err
	}

	err = u.SetCapabilityInvocation(request, actionDecrypt)
	if err != nil {
		return fmt.Errorf("user failed to set zcap: %w", err)
	}

	err = u.Sign(request)
	if err != nil {
		return fmt.Errorf("user failed to sign request: %w", err)
	}

	response, err := s.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("http do: %w", err)
	}

	defer func() {
		closeErr := response.Body.Close()
		if closeErr != nil {
			s.logger.Errorf("Failed to close response body: %s\n", closeErr.Error())
		}
	}()

	var decryptResponse decryptResp

	if respErr := u.processResponse(&decryptResponse, response); respErr != nil {
		return respErr
	}

	plainText, err := base64.URLEncoding.DecodeString(decryptResponse.PlainText)
	if err != nil {
		return err
	}

	u.response.body = map[string]string{
		"plainText": string(plainText),
	}

	return nil
}

func (s *Steps) makeComputeMACReq(userName, endpoint, data string) error {
	u := s.users[userName]

	r := &computeMACReq{
		Data: base64.URLEncoding.EncodeToString([]byte(data)),
	}

	request, err := u.preparePostRequest(r, endpoint)
	if err != nil {
		return err
	}

	err = u.SetCapabilityInvocation(request, actionComputeMac)
	if err != nil {
		return fmt.Errorf("user failed to set zcap: %w", err)
	}

	err = u.Sign(request)
	if err != nil {
		return fmt.Errorf("user failed to sign request: %w", err)
	}

	response, err := s.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("http do: %w", err)
	}

	defer func() {
		closeErr := response.Body.Close()
		if closeErr != nil {
			s.logger.Errorf("Failed to close response body: %s\n", closeErr.Error())
		}
	}()

	var computeMACResponse computeMACResp

	if respErr := u.processResponse(&computeMACResponse, response); respErr != nil {
		return respErr
	}

	mac, err := base64.URLEncoding.DecodeString(computeMACResponse.MAC)
	if err != nil {
		return err
	}

	u.response.body = map[string]string{
		"mac": string(mac),
	}

	return nil
}

func (s *Steps) makeVerifyMACReq(userName, endpoint, tag, data string) error {
	u := s.users[userName]

	r := &verifyMACReq{
		MAC:  base64.URLEncoding.EncodeToString([]byte(u.response.body[tag])),
		Data: base64.URLEncoding.EncodeToString([]byte(data)),
	}

	return s.makeVerifyReq(u, actionVerifyMAC, r, endpoint)
}

func (s *Steps) makeVerifyReq(u *user, action string, r interface{}, endpoint string) error {
	request, err := u.preparePostRequest(r, endpoint)
	if err != nil {
		return err
	}

	err = u.SetCapabilityInvocation(request, action)
	if err != nil {
		return fmt.Errorf("user failed to set zcap on request: %w", err)
	}

	err = u.Sign(request)
	if err != nil {
		return fmt.Errorf("user failed to sign request: %w", err)
	}

	response, err := s.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("http do: %w", err)
	}

	defer func() {
		closeErr := response.Body.Close()
		if closeErr != nil {
			s.logger.Errorf("Failed to close response body: %s\n", closeErr.Error())
		}
	}()

	return u.processResponse(nil, response)
}

func (s *Steps) makeWrapKeyReq(userName, endpoint, keyID, recipient string) error {
	u := s.users[userName]

	recipientPubKey := u.recipientPubKeys[recipient]

	r := &wrapReq{
		CEK: base64.URLEncoding.EncodeToString(s.keys[keyID]),
		APU: base64.URLEncoding.EncodeToString([]byte("sender")),
		APV: base64.URLEncoding.EncodeToString([]byte("recipient")),
		RecipientPubKey: publicKey{
			KID:   base64.URLEncoding.EncodeToString([]byte(recipientPubKey.KID)),
			X:     base64.URLEncoding.EncodeToString(recipientPubKey.X),
			Y:     base64.URLEncoding.EncodeToString(recipientPubKey.Y),
			Curve: base64.URLEncoding.EncodeToString([]byte(recipientPubKey.Curve)),
			Type:  base64.URLEncoding.EncodeToString([]byte(recipientPubKey.Type)),
		},
	}

	request, err := u.preparePostRequest(r, endpoint)
	if err != nil {
		return err
	}

	err = u.SetCapabilityInvocation(request, actionWrap)
	if err != nil {
		return fmt.Errorf("user failed to set zcap: %w", err)
	}

	err = u.Sign(request)
	if err != nil {
		return fmt.Errorf("user failed to sign request: %w", err)
	}

	response, err := s.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("http do: %w", err)
	}

	defer func() {
		closeErr := response.Body.Close()
		if closeErr != nil {
			s.logger.Errorf("Failed to close response body: %s\n", closeErr.Error())
		}
	}()

	var wrapResponse wrapResp

	if respErr := u.processResponse(&wrapResponse, response); respErr != nil {
		return respErr
	}

	wrappedKey, err := json.Marshal(wrapResponse.WrappedKey)
	if err != nil {
		return err
	}

	u.response.body = map[string]string{
		"wrappedKey": string(wrappedKey),
	}

	return nil
}

func (s *Steps) makeUnwrapKeyReq(userName, endpoint, tag, sender string) error {
	u := s.users[userName]

	wrappedKeyContent := s.users[sender].response.body[tag]

	var wrappedKey recipientWrappedKey

	err := json.Unmarshal([]byte(wrappedKeyContent), &wrappedKey)
	if err != nil {
		return err
	}

	r := &unwrapReq{
		WrappedKey: wrappedKey,
		SenderKID:  "",
	}

	request, err := u.preparePostRequest(r, endpoint)
	if err != nil {
		return err
	}

	err = u.SetCapabilityInvocation(request, actionUnwrap)
	if err != nil {
		return fmt.Errorf("user failed to set zcap: %w", err)
	}

	err = u.Sign(request)
	if err != nil {
		return fmt.Errorf("user failed to sign request: %w", err)
	}

	response, err := s.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("http do: %w", err)
	}

	defer func() {
		closeErr := response.Body.Close()
		if closeErr != nil {
			s.logger.Errorf("Failed to close response body: %s\n", closeErr.Error())
		}
	}()

	var unwrapResponse unwrapResp

	if respErr := u.processResponse(&unwrapResponse, response); respErr != nil {
		return respErr
	}

	key, err := base64.URLEncoding.DecodeString(unwrapResponse.Key)
	if err != nil {
		return err
	}

	u.response.body = map[string]string{
		"key": string(key),
	}

	return nil
}

func (s *Steps) getPubKeyOfRecipient(userName, recipientName string) error {
	u := s.users[userName]
	recipient := s.users[recipientName]

	request, err := recipient.prepareGetRequest(s.bddContext.KeyServerURL + exportKeyEndpoint)
	if err != nil {
		return err
	}

	// recipient delegates authority on the user to export their public key
	c, err := delegateCapability(recipient.kmsCapability, recipient.signer, recipient.controller, u.controller)
	if err != nil {
		return err
	}

	err = setCapabilityHeader(request, c, u.controller, u.authKMS, u.authCrypto)
	if err != nil {
		return err
	}

	response, err := s.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("http do: %w", err)
	}

	defer func() {
		closeErr := response.Body.Close()
		if closeErr != nil {
			s.logger.Errorf("Failed to close response body: %s\n", closeErr.Error())
		}
	}()

	var exportKeyResponse exportKeyResp

	if respErr := recipient.processResponse(&exportKeyResponse, response); respErr != nil {
		return respErr
	}

	pubKeyBytes, err := base64.URLEncoding.DecodeString(exportKeyResponse.PublicKey)
	if err != nil {
		return err
	}

	pubKey := publicKeyWithBytesXY{}

	err = json.Unmarshal(pubKeyBytes, &pubKey)
	if err != nil {
		return err
	}

	s.users[userName].recipientPubKeys = map[string]publicKeyWithBytesXY{
		recipientName: pubKey,
	}

	return nil
}

func delegateCapability(c *zcapld.Capability, s signer, verificationMethod, invoker string) (string, error) {
	var chain []interface{}

	untyped, ok := c.Proof[0]["capabilityChain"].([]interface{})
	if ok {
		chain = append(chain, untyped...)
	}

	chain = append(chain, c.ID)

	delegatedCapability, err := zcapld.NewCapability(
		&zcapld.Signer{
			SignatureSuite:     ed25519signature2018.New(suite.WithSigner(s)),
			SuiteType:          ed25519signature2018.SignatureType,
			VerificationMethod: verificationMethod,
		},
		zcapld.WithInvoker(invoker),
		zcapld.WithParent(c.ID),
		zcapld.WithInvocationTarget(c.InvocationTarget.ID, c.InvocationTarget.Type),
		zcapld.WithAllowedActions(actionExportKey),
		zcapld.WithCapabilityChain(chain...),
	)
	if err != nil {
		return "", fmt.Errorf("failed to delegate zcap unto user: %w", err)
	}

	compressed, err := zcapld2.CompressZCAP(delegatedCapability)
	if err != nil {
		return "", fmt.Errorf("failed to compress zcap: %w", err)
	}

	return compressed, nil
}

func setCapabilityHeader(request *http.Request, capability string, controller string,
	k kms.KeyManager, c crypto.Crypto) error {
	request.Header.Set(
		zcapld.CapabilityInvocationHTTPHeader,
		fmt.Sprintf(`zcap capability="%s",action="%s"`, capability, actionExportKey),
	)

	hs := httpsignatures.NewHTTPSignatures(&zcapld.AriesDIDKeySecrets{})
	hs.SetSignatureHashAlgorithm(&zcapld.AriesDIDKeySignatureHashAlgorithm{
		Crypto: c,
		KMS:    k,
	})

	err := hs.Sign(controller, request)
	if err != nil {
		return fmt.Errorf("user failed to sign request: %w", err)
	}

	return nil
}

func (s *Steps) checkRespStatus(user, status string) error {
	u := s.users[user]

	if u.response.status != status {
		return fmt.Errorf("expected HTTP response status %q, got: %q", status, u.response.status)
	}

	return nil
}

func (s *Steps) checkHeaderWithValidURL(user, header string) error {
	u := s.users[user]

	_, err := url.ParseRequestURI(u.response.headers[header])
	if err != nil {
		return fmt.Errorf("expected %q header to be a valid URL, got error: %q", header, err)
	}

	return nil
}

func (s *Steps) checkRespWithNonEmptyValue(user, tag string) error {
	u := s.users[user]

	if u.response.body[tag] == "" {
		return fmt.Errorf("expected property %q to be non-empty", tag)
	}

	return nil
}

func (s *Steps) checkRespWithNoValue(user, tag string) error {
	u := s.users[user]

	v, ok := u.response.body[tag]
	if ok {
		return fmt.Errorf("expected no field %q, got with value: %q", tag, v)
	}

	return nil
}

func (s *Steps) checkRespWithValue(user, tag, val string) error {
	u := s.users[user]

	if u.response.body[tag] != val {
		return fmt.Errorf("expected %q to be %q, got: %q", tag, val, u.response.body[tag])
	}

	return nil
}

func (s *Steps) checkRespWithKeyContent(user, keyID string) error {
	u := s.users[user]

	key := []byte(u.response.body["key"])

	if !bytes.Equal(key, s.keys[keyID]) {
		return fmt.Errorf("expected key content to be %q, got: %q", base64.URLEncoding.EncodeToString(s.keys[keyID]),
			base64.URLEncoding.EncodeToString(key))
	}

	return nil
}
