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

	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
	"github.com/rs/xid"
	"github.com/trustbloc/edge-core/pkg/sss/base"
	"github.com/trustbloc/edge-core/pkg/zcapld"
	"github.com/trustbloc/edv/pkg/client"
	"github.com/trustbloc/edv/pkg/restapi/models"
	authlogin "github.com/trustbloc/hub-auth/test/bdd/pkg/login"

	"github.com/trustbloc/kms/test/bdd/pkg/internal/cryptoutil"
)

const (
	edvBasePath    = "/encrypted-data-vaults"
	secretEndpoint = "/secret"
)

func (s *Steps) storeSecretInHubAuth(userName string) error {
	u := &user{
		name: userName,
	}
	s.users[userName] = u

	secretA, secretB, err := createSecretShares()
	if err != nil {
		return err
	}

	u.secretShare = secretA

	login := authlogin.NewSteps(s.authBDDContext)

	wallet, err := login.NewWalletLogin()
	if err != nil {
		return err
	}

	u.subject = wallet.UserData.Sub
	u.accessToken = s.authBDDContext.AccessToken()

	r := setSecretRequest{
		Secret: secretB,
	}

	request, err := u.preparePostRequest(r, s.bddContext.HubAuthURL+secretEndpoint)
	if err != nil {
		return err
	}

	token := base64.StdEncoding.EncodeToString([]byte(s.authBDDContext.AccessToken()))

	request.Header.Set("authorization", fmt.Sprintf("Bearer %s", token))

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

func createSecretShares() ([]byte, []byte, error) {
	const splitParts = 2

	splitter := base.Splitter{}

	secrets, err := splitter.Split(cryptoutil.GenerateKey(), splitParts, splitParts)
	if err != nil {
		return nil, nil, err
	}

	return secrets[0], secrets[1], nil
}

func (s *Steps) createEDVDataVault(userName string) error {
	u := s.users[userName]

	authzUser := &user{
		name:        userName,
		subject:     u.subject,
		secretShare: u.secretShare,
		accessToken: u.accessToken,
	}

	config, err := s.prepareDataVaultConfig(authzUser)
	if err != nil {
		return err
	}

	c := client.New(s.bddContext.EDVServerURL+edvBasePath, client.WithTLSConfig(s.bddContext.TLSConfig()))

	vaultURL, resp, err := c.CreateDataVault(config)
	if err != nil {
		return err
	}

	edvCapability, err := zcapld.ParseCapability(resp)
	if err != nil {
		return err
	}

	parts := strings.Split(vaultURL, "/")

	u.vaultID = parts[len(parts)-1]
	u.controller = config.Controller
	u.signer = newAuthzKMSSigner(s, authzUser)
	u.edvCapability = edvCapability

	u.authKMS = &remoteKMS{
		keystoreID: u.keystoreID,
	}

	u.authCrypto = &remoteAuthCrypto{
		baseURL: s.bddContext.AuthZKeyServerURL,
		httpClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: s.bddContext.TLSConfig(),
			},
		},
		user: u,
	}

	return nil
}

func (s *Steps) prepareDataVaultConfig(u *user) (*models.DataVaultConfiguration, error) {
	err := s.createKeystoreAuthzKMS(u)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth keystore: %w", err)
	}

	if errCreate := s.makeCreateKeyReqAuthzKMS(u,
		s.bddContext.AuthZKeyServerURL+keysEndpoint, "ED25519"); errCreate != nil {
		return nil, fmt.Errorf("failed to create auth keystore key: %w", errCreate)
	}

	if errExport := s.makeExportPubKeyReqAuthzKMS(u,
		s.bddContext.AuthZKeyServerURL+exportKeyEndpoint); errExport != nil {
		return nil, fmt.Errorf("failed to export authz keystore key: %w", errExport)
	}

	pkBytes := []byte(u.data["publicKey"])

	_, didKey := fingerprint.CreateDIDKey(pkBytes)

	return &models.DataVaultConfiguration{
		Sequence:    0,
		Controller:  didKey,
		ReferenceID: xid.New().String(),
		KEK:         models.IDTypePair{ID: "https://example.com/kms/12345", Type: "AesKeyWrappingKey2019"},
		HMAC:        models.IDTypePair{ID: "https://example.com/kms/67891", Type: "Sha256HmacKey2019"},
	}, nil
}

func (s *Steps) createKeystoreAuthzKMS(u *user) error {
	r := createKeystoreReq{
		Controller: u.name,
	}

	request, err := u.preparePostRequest(r, s.bddContext.AuthZKeyServerURL+createKeystoreEndpoint)
	if err != nil {
		return err
	}

	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", u.accessToken))
	request.Header.Set("Kms-Secret", base64.StdEncoding.EncodeToString(u.secretShare))

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

	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", u.accessToken))
	request.Header.Set("Kms-Secret", base64.StdEncoding.EncodeToString(u.secretShare))

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

	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", u.accessToken))
	request.Header.Set("Kms-Secret", base64.StdEncoding.EncodeToString(u.secretShare))

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

	u.data = map[string]string{
		"publicKey": string(publicKey),
	}

	return nil
}

func (s *Steps) makeSignMessageReqAuthzKMS(u *user, endpoint, message string) error {
	r := signReq{
		Message: message,
	}

	request, err := u.preparePostRequest(r, endpoint)
	if err != nil {
		return err
	}

	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", u.accessToken))
	request.Header.Set("Kms-Secret", base64.StdEncoding.EncodeToString(u.secretShare))

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

	u.data = map[string]string{
		"signature": string(signature),
	}

	return nil
}
