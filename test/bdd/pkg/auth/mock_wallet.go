/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/ory/hydra-client-go/client"
	"github.com/ory/hydra-client-go/client/admin"
	"github.com/ory/hydra-client-go/models"
	"github.com/rs/xid"
	"golang.org/x/oauth2"
)

// MockWallet is a mock wallet.
type MockWallet struct {
	oidcProvider     *oidc.Provider
	httpClient       *http.Client
	clientID         string
	clientSecret     string
	scope            []string
	server           *httptest.Server
	oauth2Config     oauth2.Config
	accessToken      string
	ReceivedCallback bool
	UserData         *UserClaims
	CallbackErr      error
	Secret           string
}

// RequestUserAuthentication requests the user authentication from the OIDC provider.
func (m *MockWallet) RequestUserAuthentication() (*http.Response, error) {
	m.oauth2Config = oauth2.Config{
		ClientID:     m.clientID,
		ClientSecret: m.clientSecret,
		Endpoint:     m.oidcProvider.Endpoint(),
		RedirectURL:  m.server.URL,
		Scopes:       m.scope,
	}

	redirectURL := m.oauth2Config.AuthCodeURL("dont_care_about_state")

	response, err := m.httpClient.Get(redirectURL) //nolint:noctx
	if err != nil {
		return nil, fmt.Errorf("failed to send authentication request %s: %w", redirectURL, err)
	}

	return response, nil
}

// ServeHTTP serves HTTP requests for the wallet.
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

// NewMockWallet returns a new instance of the mock wallet.
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
		clientID:     xid.New().String(),
		clientSecret: xid.New().String(),
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

	_, err = hydraClient.CreateOAuth2Client(request) //nolint:errcheck
	if err != nil {
		return nil, fmt.Errorf("failed to register auth as an oidc client of hub auth: %w", err)
	}

	return wallet, nil
}
