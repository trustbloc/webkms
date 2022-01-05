/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"github.com/ory/hydra-client-go/client"
	"github.com/ory/hydra-client-go/client/admin"
	"github.com/ory/hydra-client-go/models"
	"golang.org/x/oauth2"

	"github.com/trustbloc/hub-auth/pkg/restapi/operation"
)

type MockWallet struct {
	oidcProvider     *oidc.Provider
	httpClient       *http.Client
	clientID         string
	clientSecret     string
	scope            []string
	server           *httptest.Server
	oauth2Config     oauth2.Config
	receivedCallback bool
	userData         *UserClaims
	callbackErr      error
	accessToken      string
	ReceivedCallback bool
	UserData         *UserClaims
	CallbackErr      error
	Secret           string
}

func (m *MockWallet) RequestUserAuthentication() (*http.Response, error) {
	m.oauth2Config = oauth2.Config{
		ClientID:     m.clientID,
		ClientSecret: m.clientSecret,
		Endpoint:     m.oidcProvider.Endpoint(),
		RedirectURL:  m.server.URL,
		Scopes:       m.scope,
	}

	redirectURL := m.oauth2Config.AuthCodeURL("dont_care_about_state")

	response, err := m.httpClient.Get(redirectURL)
	if err != nil {
		return nil, fmt.Errorf("failed to send authentication request %s: %w", redirectURL, err)
	}

	return response, nil
}

func (m *MockWallet) FetchBootstrapData(endpoint string) (*operation.BootstrapData, error) {
	request, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to construct http request: %w", err)
	}

	m.addAccessToken(request)

	response, err := m.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("failed to invoke bootstrap data endpoint: %w", err)
	}

	defer func() {
		closeErr := response.Body.Close()
		if closeErr != nil {
			fmt.Printf("WARNING - failed to close http response body: %s\n", closeErr.Error())
		}
	}()

	if response.StatusCode != http.StatusOK {
		msg, err := ioutil.ReadAll(response.Body)
		if err != nil {
			fmt.Printf("WARNING - failed to read response body: %s\n", err.Error())
		}

		return nil, fmt.Errorf(
			"unexpected response: code=%d msg=%s", response.StatusCode, msg,
		)
	}

	data := &operation.BootstrapData{}

	return data, json.NewDecoder(response.Body).Decode(data)
}

func (m *MockWallet) UpdateBootstrapData(endpoint string, update *operation.UpdateBootstrapDataRequest) error {
	payload, err := json.Marshal(update)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	request, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("failed to create http request: %w", err)
	}

	m.addAccessToken(request)

	response, err := m.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("failed to invoke bootstrap data endpoint: %w", err)
	}

	defer func() {
		closeErr := response.Body.Close()
		if closeErr != nil {
			fmt.Printf("WARNING - failed to close http response body: %s\n", closeErr.Error())
		}
	}()

	if response.StatusCode != http.StatusOK {
		msg, err := ioutil.ReadAll(response.Body)
		if err != nil {
			fmt.Printf("WARNING - failed to read response body: %s\n", err.Error())
		}

		return fmt.Errorf(
			"unexpected response: code=%d msg=%s", response.StatusCode, msg,
		)
	}

	return nil
}

func (m *MockWallet) CreateAndPushSecretToHubAuth(endpoint string) error {
	m.Secret = uuid.New().String()

	payload, err := json.Marshal(&operation.SetSecretRequest{
		Secret: []byte(m.Secret),
	})
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	request, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("failed to create http request: %w", err)
	}

	m.addAccessToken(request)

	response, err := m.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("failed to push secret to hub-auth: %w", err)
	}

	defer func() {
		closeErr := response.Body.Close()
		if closeErr != nil {
			fmt.Printf("WARNING - failed to close response body: %s\n", closeErr.Error())
		}
	}()

	if response.StatusCode != http.StatusOK {
		msg, err := ioutil.ReadAll(response.Body)
		if err != nil {
			fmt.Printf("WARNING - failed to read response body: %s\n", err.Error())
		}

		return fmt.Errorf(
			"unexpected response: code=%d msg=%s", response.StatusCode, msg,
		)
	}

	return nil
}

func (m *MockWallet) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.ReceivedCallback = true

	code := r.URL.Query().Get("code")
	if code == "" {
		m.CallbackErr = errors.New("did not get a code in the callback")

		return
	}

	token, err := m.oauth2Config.Exchange(
		context.WithValue(r.Context(), oauth2.HTTPClient, m.httpClient),
		code,
	)
	if err != nil {
		m.CallbackErr = fmt.Errorf("failed to exchange code for token: %w", err)

		return
	}

	m.accessToken = token.AccessToken

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		m.CallbackErr = errors.New("missing id_token")

		return
	}

	idToken, err := m.oidcProvider.Verifier(&oidc.Config{ClientID: m.clientID}).Verify(r.Context(), rawIDToken)
	if err != nil {
		m.CallbackErr = fmt.Errorf("failed to verify id_token: %w", err)

		return
	}

	m.UserData = &UserClaims{}

	err = idToken.Claims(m.UserData)
	if err != nil {
		m.CallbackErr = fmt.Errorf("failed to extract claims from id_token: %w", err)

		return
	}

	_, err = w.Write([]byte("mock auth authenticated the user!"))
	if err != nil {
		m.CallbackErr = fmt.Errorf("failed to render mock UI to the user: %w", err)

		return
	}

	// store access token
	m.accessToken = token.AccessToken
}

func (m *MockWallet) addAccessToken(r *http.Request) {
	r.Header.Set(
		"authorization",
		fmt.Sprintf("Bearer %s", base64.StdEncoding.EncodeToString([]byte(m.accessToken))),
	)
}

func NewMockWallet(clientRegistrationURL, oidcProviderURL string, httpClient *http.Client) (*MockWallet, error) {
	oidcProvider, err := oidc.NewProvider(
		oidc.ClientContext(context.Background(), httpClient),
		oidcProviderURL,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to init oidc provider: %w, %s", err, oidcProviderURL)
	}

	wallet := &MockWallet{
		oidcProvider: oidcProvider,
		httpClient:   httpClient,
		clientID:     uuid.New().String(),
		clientSecret: uuid.New().String(),
		scope:        []string{oidc.ScopeOpenID},
	}
	wallet.server = httptest.NewServer(wallet)

	request := admin.NewCreateOAuth2ClientParams()
	request.SetHTTPClient(wallet.httpClient)
	request.SetBody(&models.OAuth2Client{
		ClientID:      wallet.clientID,
		ClientSecret:  wallet.clientSecret,
		GrantTypes:    []string{"authorization_code", "refresh_token"},
		ResponseTypes: []string{"code", "id_token"},
		Scope:         strings.Join(wallet.scope, " "),
		RedirectUris:  []string{wallet.server.URL},
	})

	hydraAdminURL, err := url.Parse(clientRegistrationURL)
	if err != nil {
		return nil, fmt.Errorf("invalid hydra admin url: %s", clientRegistrationURL)
	}

	hydraClient := client.NewHTTPClientWithConfig(nil,
		&client.TransportConfig{
			Host:     hydraAdminURL.Host,
			BasePath: hydraAdminURL.Path,
			Schemes:  []string{hydraAdminURL.Scheme},
		},
	).Admin

	_, err = hydraClient.CreateOAuth2Client(request)
	if err != nil {
		return nil, fmt.Errorf("failed to register auth as an oidc client of hub auth: %w", err)
	}

	return wallet, nil
}
