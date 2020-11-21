/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
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
	edvBasePath            = "/encrypted-data-vaults"
	createKeystoreEndpoint = "/kms/keystores"
	keysEndpoint           = "/kms/keystores/{keystoreID}/keys"
	exportKeyEndpoint      = "/kms/keystores/{keystoreID}/keys/{keyID}/export"
)

const (
	keySize = sha256.Size
)

// Steps defines steps context for the KMS operations.
type Steps struct {
	bddContext *context.BDDContext
	logger     log.Logger
	users      map[string]*user
	keys       map[string][]byte
}

// NewSteps creates steps context for the KMS operations.
func NewSteps() *Steps {
	return &Steps{
		logger: log.New("kms-rest/tests/kms"),
		users:  map[string]*user{},
		keys:   map[string][]byte{"testCEK": randomBytes(keySize)},
	}
}

// SetContext sets a fresh context for every scenario.
func (s *Steps) SetContext(ctx *context.BDDContext) {
	s.bddContext = ctx
}

// RegisterSteps defines scenario steps.
func (s *Steps) RegisterSteps(ctx *godog.ScenarioContext) {
	// common creation steps
	ctx.Step(`^"([^"]*)" has created a data vault on SDS Server for storing operational keys$`, s.createEDVDataVault)
	ctx.Step(`^"([^"]*)" has created an empty keystore on Key Server$`, s.createKeystore)
	ctx.Step(`^"([^"]*)" has created a keystore with "([^"]*)" key on Key Server$`, s.createKeystoreAndKey)
	// common response checking steps
	ctx.Step(`^"([^"]*)" gets a response with HTTP status "([^"]*)"$`, s.checkRespStatus)
	ctx.Step(`^"([^"]*)" gets a response with "([^"]*)" header with a valid URL$`, s.checkHeaderWithValidURL)
	ctx.Step(`^"([^"]*)" gets a response with non-empty "([^"]*)"$`, s.checkRespWithNonEmptyValue)
	ctx.Step(`^"([^"]*)" gets a response with no "([^"]*)"$`, s.checkRespWithNoValue)
	ctx.Step(`^"([^"]*)" gets a response with "([^"]*)" with value "([^"]*)"$`, s.checkRespWithValue)
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
	ctx.Step(`^"([^"]*)" gets a response with content of "([^"]*)" key$`, s.checkRespWithKeyContent)
}

func (s *Steps) createEDVDataVault(userName string) error {
	config := models.DataVaultConfiguration{
		Sequence:    0,
		Controller:  "did:example:123456789",
		ReferenceID: xid.New().String(),
		KEK:         models.IDTypePair{ID: "https://example.com/kms/12345", Type: "AesKeyWrappingKey2019"},
		HMAC:        models.IDTypePair{ID: "https://example.com/kms/67891", Type: "Sha256HmacKey2019"},
	}

	c := client.New(s.bddContext.SDSServerURL+edvBasePath, client.WithTLSConfig(s.bddContext.TLSConfig()))

	vaultURL, _, err := c.CreateDataVault(&config)
	if err != nil {
		return err
	}

	parts := strings.Split(vaultURL, "/")

	_, ok := s.users[userName]
	if !ok {
		u := &user{
			name:    userName,
			vaultID: parts[len(parts)-1],
		}

		s.users[userName] = u
	}

	return nil
}

func (s *Steps) createKeystore(user string) error {
	u := s.users[user]

	req := createKeystoreReq{
		Controller:         u.controller,
		OperationalVaultID: u.vaultID,
	}

	resp, closeBody, err := s.post(u, s.bddContext.KeyServerURL+createKeystoreEndpoint, req)
	if err != nil {
		return err
	}

	defer closeBody()

	return u.processResponse(nil, resp)
}

func (s *Steps) createKeystoreAndKey(user, keyType string) error {
	err := s.createKeystore(user)
	if err != nil {
		return err
	}

	return s.makeCreateKeyReq(user, s.bddContext.KeyServerURL+keysEndpoint, keyType)
}

func (s *Steps) makeCreateKeyReq(user, endpoint, keyType string) error {
	u := s.users[user]

	req := createKeyReq{
		KeyType: keyType,
	}

	resp, closeBody, err := s.post(u, endpoint, req)
	if err != nil {
		return err
	}

	defer closeBody()

	return u.processResponse(nil, resp)
}

func (s *Steps) makeExportPubKeyReq(user, endpoint string) error {
	u := s.users[user]

	resp, closeBody, err := s.get(u, endpoint)
	if err != nil {
		return err
	}

	defer closeBody()

	var parsedResp exportKeyResp

	err = u.processResponse(&parsedResp, resp)
	if err != nil {
		return err
	}

	u.response.body = map[string]string{
		"publicKey": parsedResp.PublicKey,
	}

	return nil
}

func (s *Steps) makeSignMessageReq(user, endpoint, message string) error {
	u := s.users[user]

	req := signReq{
		Message: message,
	}

	resp, closeBody, err := s.post(u, endpoint, req)
	if err != nil {
		return err
	}

	defer closeBody()

	var parsedResp signResp

	err = u.processResponse(&parsedResp, resp)
	if err != nil {
		return err
	}

	u.response.body = map[string]string{
		"signature": parsedResp.Signature,
	}

	return nil
}

func (s *Steps) makeVerifySignatureReq(user, endpoint, tag, message string) error {
	u := s.users[user]

	req := &verifyReq{
		Signature: u.response.body[tag],
		Message:   message,
	}

	resp, closeBody, err := s.post(u, endpoint, req)
	if err != nil {
		return err
	}

	defer closeBody()

	return u.processResponse(nil, resp)
}

func (s *Steps) makeEncryptMessageReq(user, endpoint, message string) error {
	u := s.users[user]

	req := &encryptReq{
		Message:        message,
		AdditionalData: "additional data",
	}

	resp, closeBody, err := s.post(u, endpoint, req)
	if err != nil {
		return err
	}

	defer closeBody()

	var parsedResp encryptResp

	err = u.processResponse(&parsedResp, resp)
	if err != nil {
		return err
	}

	u.response.body = map[string]string{
		"cipherText": parsedResp.CipherText,
		"nonce":      parsedResp.Nonce,
	}

	return nil
}

func (s *Steps) makeDecryptCipherReq(user, endpoint, tag string) error {
	u := s.users[user]

	req := &decryptReq{
		CipherText:     u.response.body[tag],
		AdditionalData: "additional data",
		Nonce:          u.response.body["nonce"],
	}

	resp, closeBody, err := s.post(u, endpoint, req)
	if err != nil {
		return err
	}

	defer closeBody()

	var parsedResp decryptResp

	err = u.processResponse(&parsedResp, resp)
	if err != nil {
		return err
	}

	u.response.body = map[string]string{
		"plainText": parsedResp.PlainText,
	}

	return nil
}

func (s *Steps) makeComputeMACReq(user, endpoint, data string) error {
	u := s.users[user]

	req := &computeMACReq{
		Data: data,
	}

	resp, closeBody, err := s.post(u, endpoint, req)
	if err != nil {
		return err
	}

	defer closeBody()

	var parsedResp computeMACResp

	err = u.processResponse(&parsedResp, resp)
	if err != nil {
		return err
	}

	u.response.body = map[string]string{
		"mac": parsedResp.MAC,
	}

	return nil
}

func (s *Steps) makeVerifyMACReq(user, endpoint, tag, data string) error {
	u := s.users[user]

	req := &verifyMACReq{
		MAC:  u.response.body[tag],
		Data: data,
	}

	resp, closeBody, err := s.post(u, endpoint, req)
	if err != nil {
		return err
	}

	defer closeBody()

	return u.processResponse(nil, resp)
}

func (s *Steps) makeWrapKeyReq(user, endpoint, keyID, recipient string) error {
	u := s.users[user]

	recipientPubKey := u.recipientPubKeys[recipient]

	req := &wrapReq{
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

	resp, closeBody, err := s.post(u, endpoint, req)
	if err != nil {
		return err
	}

	defer closeBody()

	var parsedResp wrapResp

	err = u.processResponse(&parsedResp, resp)
	if err != nil {
		return err
	}

	wrappedKey, err := json.Marshal(parsedResp.WrappedKey)
	if err != nil {
		return err
	}

	u.response.body = map[string]string{
		"wrappedKey": string(wrappedKey),
	}

	return nil
}

func (s *Steps) makeUnwrapKeyReq(user, endpoint, tag, sender string) error {
	u := s.users[user]

	wrappedKeyContent := s.users[sender].response.body[tag]

	var wrappedKey recipientWrappedKey

	err := json.Unmarshal([]byte(wrappedKeyContent), &wrappedKey)
	if err != nil {
		return err
	}

	req := &unwrapReq{
		WrappedKey: wrappedKey,
		SenderKID:  "",
	}

	resp, closeBody, err := s.post(u, endpoint, req)
	if err != nil {
		return err
	}

	defer closeBody()

	var parsedResp unwrapResp

	err = u.processResponse(&parsedResp, resp)
	if err != nil {
		return err
	}

	u.response.body = map[string]string{
		"key": parsedResp.Key,
	}

	return nil
}

func (s *Steps) getPubKeyOfRecipient(user, recipient string) error {
	rec := s.users[recipient]

	//nolint:bodyclose // defer closeBody()
	resp, closeBody, err := s.get(rec, s.bddContext.KeyServerURL+exportKeyEndpoint)
	if err != nil {
		return err
	}

	defer closeBody()

	var parsedResp exportKeyResp

	err = json.NewDecoder(resp.Body).Decode(&parsedResp)
	if err != nil {
		return err
	}

	pubKeyBytes, err := base64.URLEncoding.DecodeString(parsedResp.PublicKey)
	if err != nil {
		return err
	}

	pubKey := publicKeyWithBytesXY{}

	err = json.Unmarshal(pubKeyBytes, &pubKey)
	if err != nil {
		return err
	}

	s.users[user].recipientPubKeys = map[string]publicKeyWithBytesXY{
		recipient: pubKey,
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

	key, err := base64.URLEncoding.DecodeString(u.response.body["key"])
	if err != nil {
		return err
	}

	if !bytes.Equal(key, s.keys[keyID]) {
		return fmt.Errorf("expected key content to be %q, got: %q", base64.URLEncoding.EncodeToString(s.keys[keyID]),
			base64.URLEncoding.EncodeToString(key))
	}

	return nil
}

func (s *Steps) get(u *user, endpoint string) (*http.Response, func(), error) {
	uri := buildURI(endpoint, u.keystoreID, u.keyID)

	resp, err := bddutil.HTTPDo(http.MethodGet, uri, headers(), nil, s.bddContext.TLSConfig())
	if err != nil {
		return nil, nil, err
	}

	return resp, closeBodyFunc(resp.Body, s.logger), nil
}

func (s *Steps) post(u *user, endpoint string, body interface{}) (*http.Response, func(), error) {
	uri := buildURI(endpoint, u.keystoreID, u.keyID)

	b, err := json.Marshal(body)
	if err != nil {
		return nil, nil, err
	}

	resp, err := bddutil.HTTPDo(http.MethodPost, uri, headers(), bytes.NewBuffer(b), s.bddContext.TLSConfig())
	if err != nil {
		return nil, nil, err
	}

	return resp, closeBodyFunc(resp.Body, s.logger), nil
}

func randomBytes(size uint32) []byte {
	buf := make([]byte, size)

	_, err := rand.Read(buf)
	if err != nil {
		panic(err) // out of randomness, should never happen
	}

	return buf
}

func buildURI(endpoint, keystoreID, keyID string) string {
	return strings.NewReplacer(
		"{keystoreID}", keystoreID,
		"{keyID}", keyID,
	).Replace(endpoint)
}

func headers() map[string]string {
	return map[string]string{
		"Content-Type":   "application/json",
		"Hub-Kms-Secret": "p@ssphrase",
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
