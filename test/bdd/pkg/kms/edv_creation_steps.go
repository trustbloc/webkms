/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
	"github.com/rs/xid"
	"github.com/trustbloc/edge-core/pkg/zcapld"
	"github.com/trustbloc/edv/pkg/client"
	"github.com/trustbloc/edv/pkg/restapi/models"
)

const (
	edvBasePath = "/encrypted-data-vaults"
)

func (s *Steps) createEDVDataVault(userName string) error { //nolint:funlen // ignore
	u, ok := s.users[userName]
	if !ok {
		u = &user{name: userName}

		s.users[userName] = u
	}

	authzUser := &user{name: userName}
	authzUser.subject = u.subject
	authzUser.secret = u.secret

	err := s.createKeystoreAuthzKMS(authzUser)
	if err != nil {
		return fmt.Errorf("failed to create auth keystore: %w", err)
	}

	if errCreate := s.makeCreateKeyReqAuthzKMS(authzUser,
		s.bddContext.AuthZKeyServerURL+keysEndpoint, "ED25519"); errCreate != nil {
		return fmt.Errorf("failed to create auth keystore key: %w", errCreate)
	}

	if errExport := s.makeExportPubKeyReqAuthzKMS(authzUser,
		s.bddContext.AuthZKeyServerURL+exportKeyEndpoint); errExport != nil {
		return fmt.Errorf("failed to export authz keystore key: %w", errExport)
	}

	pkBytes := []byte(authzUser.response.body["publicKey"])

	_, didKey := fingerprint.CreateDIDKey(pkBytes)

	config := models.DataVaultConfiguration{
		Sequence:    0,
		Controller:  didKey,
		ReferenceID: xid.New().String(),
		KEK:         models.IDTypePair{ID: "https://example.com/kms/12345", Type: "AesKeyWrappingKey2019"},
		HMAC:        models.IDTypePair{ID: "https://example.com/kms/67891", Type: "Sha256HmacKey2019"},
	}

	c := client.New(s.bddContext.EDVServerURL+edvBasePath, client.WithTLSConfig(s.bddContext.TLSConfig()))

	vaultURL, resp, err := c.CreateDataVault(&config)
	if err != nil {
		return err
	}

	parts := strings.Split(vaultURL, "/")

	edvCapability, err := zcapld.ParseCapability(resp)
	if err != nil {
		return err
	}

	u.vaultID = parts[len(parts)-1]
	u.controller = didKey
	u.signer = newAuthzKMSSigner(s, authzUser)
	u.edvCapability = edvCapability

	u.authKMS = &remoteKMS{keystoreID: u.keystoreID}
	u.authCrypto = &remoteAuthCrypto{
		baseURL: s.bddContext.AuthZKeyServerURL,
		httpClient: &http.Client{Transport: &http.Transport{
			TLSClientConfig: s.bddContext.TLSConfig(),
		}},
		user: u,
	}

	return nil
}

func (s *Steps) createKeystoreAuthzKMS(u *user) error {
	r := createKeystoreReq{
		Controller: u.name,
	}

	request, err := u.preparePostRequest(r, s.bddContext.AuthZKeyServerURL+createKeystoreEndpoint)
	if err != nil {
		return err
	}

	request.Header.Set("Hub-Kms-User", u.subject)
	request.Header.Set("Hub-Kms-Secret", base64.StdEncoding.EncodeToString(u.secret))

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

func (s *Steps) makeCreateKeyReqAuthzKMS(u *user, endpoint, keyType string) error {
	r := createKeyReq{
		KeyType: keyType,
	}

	request, err := u.preparePostRequest(r, endpoint)
	if err != nil {
		return err
	}

	request.Header.Set("Hub-Kms-User", u.subject)
	request.Header.Set("Hub-Kms-Secret", base64.StdEncoding.EncodeToString(u.secret))

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

func (s *Steps) makeExportPubKeyReqAuthzKMS(u *user, endpoint string) error {
	request, err := u.prepareGetRequest(endpoint)
	if err != nil {
		return err
	}

	request.Header.Set("Hub-Kms-User", u.subject)
	request.Header.Set("Hub-Kms-Secret", base64.StdEncoding.EncodeToString(u.secret))

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

type authzKMSSigner struct {
	s         *Steps
	authzUser *user
}

func newAuthzKMSSigner(s *Steps, authzUser *user) *authzKMSSigner {
	return &authzKMSSigner{s: s, authzUser: authzUser}
}

func (a *authzKMSSigner) Sign(data []byte) ([]byte, error) {
	if err := a.s.makeSignMessageReqAuthzKMS(a.authzUser,
		a.s.bddContext.AuthZKeyServerURL+signEndpoint, base64.URLEncoding.EncodeToString(data)); err != nil {
		return nil, err
	}

	return []byte(a.authzUser.response.body["signature"]), nil
}

func (s *Steps) makeSignMessageReqAuthzKMS(u *user, endpoint, message string) error {
	r := signReq{
		Message: message,
	}

	request, err := u.preparePostRequest(r, endpoint)
	if err != nil {
		return err
	}

	request.Header.Set("Hub-Kms-User", u.subject)
	request.Header.Set("Hub-Kms-Secret", base64.StdEncoding.EncodeToString(u.secret))

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

type remoteKMS struct {
	keystoreID string
}

func (r *remoteKMS) Create(kt kms.KeyType) (string, interface{}, error) {
	panic("implement me")
}

func (r *remoteKMS) Get(keyID string) (interface{}, error) {
	return keyID, nil
}

func (r *remoteKMS) Rotate(kt kms.KeyType, keyID string) (string, interface{}, error) {
	panic("implement me")
}

func (r *remoteKMS) ExportPubKeyBytes(keyID string) ([]byte, error) {
	panic("implement me")
}

func (r *remoteKMS) CreateAndExportPubKeyBytes(kt kms.KeyType) (string, []byte, error) {
	panic("implement me")
}

func (r *remoteKMS) PubKeyBytesToHandle(pubKey []byte, kt kms.KeyType) (interface{}, error) {
	panic("implement me")
}

func (r *remoteKMS) ImportPrivateKey(
	privKey interface{}, kt kms.KeyType, opts ...kms.PrivateKeyOpts) (string, interface{}, error) {
	panic("implement me")
}

type remoteAuthCrypto struct {
	baseURL    string
	httpClient *http.Client
	user       *user
}

func (r *remoteAuthCrypto) Encrypt(msg, aad []byte, kh interface{}) ([]byte, []byte, error) {
	panic("implement me")
}

func (r *remoteAuthCrypto) Decrypt(cipher, aad, nonce []byte, kh interface{}) ([]byte, error) {
	panic("implement me")
}

func (r *remoteAuthCrypto) Sign(msg []byte, _ interface{}) ([]byte, error) {
	sig, err := r.user.signer.Sign(msg)
	if err != nil {
		return nil, fmt.Errorf("user's signer failed to sign: %w", err)
	}

	return sig, nil
}

func (r *remoteAuthCrypto) Verify(signature, msg []byte, kh interface{}) error {
	panic("implement me")
}

func (r *remoteAuthCrypto) ComputeMAC(data []byte, kh interface{}) ([]byte, error) {
	panic("implement me")
}

func (r *remoteAuthCrypto) VerifyMAC(mac, data []byte, kh interface{}) error {
	panic("implement me")
}

func (r *remoteAuthCrypto) WrapKey(cek, apu, apv []byte,
	recPubKey *crypto.PublicKey, opts ...crypto.WrapKeyOpts) (*crypto.RecipientWrappedKey, error) {
	panic("implement me")
}

func (r *remoteAuthCrypto) UnwrapKey(
	recWK *crypto.RecipientWrappedKey, kh interface{}, opts ...crypto.WrapKeyOpts) ([]byte, error) {
	panic("implement me")
}
