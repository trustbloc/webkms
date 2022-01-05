/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"strings"

	"github.com/google/uuid"
)

const (
	hubAuthHydraAdminURL             = "https://localhost:4445"
	hubAuthOIDCProviderURL           = "https://localhost:4444/"
	hubAuthOIDCProviderSelectionPath = "/ui"
	hubAuthSelectOIDCProviderPath    = "/oauth2/login"
	mockLoginURL                     = "https://localhost:8099/mock/login"
	mockAuthenticationURL            = "https://localhost:8099/mock/authn"
	mockConsentURL                   = "https://localhost:8099/mock/consent"
	mockAuthorizationURL             = "https://localhost:8099/mock/authz"
	mockOIDCProviderName             = "mockbank" // providers.yaml
)

// LoginConfig sets services urls and names needed for auth login.
type LoginConfig struct {
	HubAuthHydraAdminURL            string
	HubAuthOIDCProviderURL          string
	HubAuthOIDCProviderSelectionURL string
	HubAuthSelectOIDCProviderURL    string
	LoginURL                        string
	AuthenticationURL               string
	ConsentURL                      string
	AuthorizationURL                string
	OIDCProviderName                string
}

// defines the payload expected by the login consent server's /authn endpoint
type userAuthenticationConfig struct {
	Sub  string `json:"sub"`
	Fail bool   `json:"fail,omitempty"`
}

type userAuthorizationConfig struct {
	UserClaims *UserClaims `json:"user_claims,omitempty"`
	Fail       bool        `json:"fail,omitempty"`
}

// UserClaims can be configured by BDD tests.
type UserClaims struct {
	Sub        string `json:"sub"`
	Name       string `json:"name"`
	GivenName  string `json:"given_name"`
	FamilyName string `json:"family_name"`
	Email      string `json:"email"`
}

// AuthLogin used for wallet login.
type AuthLogin struct {
	browser          *http.Client
	tlsConfig        *tls.Config
	cfg              *LoginConfig
	wallet           *MockWallet
	expectedUserData *UserClaims
}

// NewAuthLogin returns new instance of AuthLogin.
func NewAuthLogin(loginConfig *LoginConfig, tlsConfig *tls.Config) *AuthLogin {
	return &AuthLogin{cfg: loginConfig, tlsConfig: tlsConfig}
}

// WalletLogin logins and return a new MockWallet that is logged in.
func (a *AuthLogin) WalletLogin() (*MockWallet, string, error) {
	err := a.registerWallet()
	if err != nil {
		return nil, "", err
	}

	err = a.redirectUserToAuthenticate()
	if err != nil {
		return nil, "", err
	}

	err = a.selectThirdPartyOIDCProvider()
	if err != nil {
		return nil, "", err
	}

	err = a.authenticateUserAtThirdPartyProvider()
	if err != nil {
		return nil, "", err
	}

	err = a.checkIsUserRedirectedBackToWallet()
	if err != nil {
		return nil, "", err
	}

	return a.wallet, a.wallet.accessToken, a.checkIsUserAuthenticatedToTheWallet()
}

func (a *AuthLogin) registerWallet() error {
	err := a.initBrowser()
	if err != nil {
		return fmt.Errorf("failed to register auth: %w", err)
	}

	a.wallet, err = NewMockWallet(a.cfg.HubAuthHydraAdminURL, a.cfg.HubAuthOIDCProviderURL, a.browser)
	if err != nil {
		return fmt.Errorf("failed to register auth: %w", err)
	}

	return nil
}

func (a *AuthLogin) redirectUserToAuthenticate() error {
	result, err := a.wallet.RequestUserAuthentication()
	if err != nil {
		return fmt.Errorf("auth failed to redirect user for authentication: %w", err)
	}

	if result.Request.URL.String() != a.cfg.HubAuthOIDCProviderSelectionURL {
		return fmt.Errorf(
			"the user ended up at the wrong login URL; expected %s got %s",
			a.cfg.HubAuthOIDCProviderSelectionURL, result.Request.URL.String(),
		)
	}

	return nil
}

func (a *AuthLogin) selectThirdPartyOIDCProvider() error {
	request := fmt.Sprintf("%s?provider=%s", a.cfg.HubAuthSelectOIDCProviderURL, a.cfg.OIDCProviderName)

	result, err := a.browser.Get(request)
	if err != nil {
		return fmt.Errorf("user failed to select OIDC provider using request %s: %w", request, err)
	}

	if !strings.HasPrefix(result.Request.URL.String(), a.cfg.LoginURL) {
		return fmt.Errorf(
			"user at wrong third party OIDC provider; expected %s got %s",
			a.cfg.LoginURL, result.Request.URL.String(),
		)
	}

	return nil
}

func (a *AuthLogin) authenticateUserAtThirdPartyProvider() error {
	a.expectedUserData = &UserClaims{
		Sub:        uuid.New().String(),
		Name:       "John Smith",
		GivenName:  "John",
		FamilyName: "Smith",
		Email:      "john.smith@example.org",
	}

	authn, err := json.Marshal(&userAuthenticationConfig{
		Sub: a.expectedUserData.Sub,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal user authn config: %w", err)
	}

	response, err := a.browser.Post(a.cfg.AuthenticationURL, "application/json", bytes.NewReader(authn))
	if err != nil {
		return fmt.Errorf("user failed to send authentication data: %w", err)
	}

	if !strings.HasPrefix(response.Request.URL.String(), a.cfg.ConsentURL) {
		return fmt.Errorf(
			"user is at the wrong third party consent url; expected %s got %s",
			a.cfg.ConsentURL, response.Request.URL.String(),
		)
	}

	authz, err := json.Marshal(&userAuthorizationConfig{
		UserClaims: a.expectedUserData,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal user authz config: %w", err)
	}

	response, err = a.browser.Post(a.cfg.AuthorizationURL, "application/json", bytes.NewReader(authz))
	if err != nil {
		return fmt.Errorf("user failed to send authorization data: %w, %s", err, a.cfg.AuthorizationURL)
	}

	if response.StatusCode != http.StatusOK {
		msg, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %w", err)
		}

		return fmt.Errorf(
			"unexpected status code; expected %d got %d msg=%s",
			http.StatusOK, response.StatusCode, msg,
		)
	}

	return nil
}

func (a *AuthLogin) checkIsUserRedirectedBackToWallet() error {
	if !a.wallet.ReceivedCallback {
		return fmt.Errorf("the auth has not received a callback")
	}

	return nil
}

func (a *AuthLogin) checkIsUserAuthenticatedToTheWallet() error {
	if a.wallet.CallbackErr != nil {
		return fmt.Errorf("auth failed to execute callback successfully: %w", a.wallet.CallbackErr)
	}

	if a.wallet.UserData.Sub != a.expectedUserData.Sub {
		return fmt.Errorf(
			"auth received a different user idenfitier than expected; expected %s got %s",
			a.expectedUserData.Sub, a.wallet.UserData.Sub,
		)
	}

	return nil
}

func (a *AuthLogin) initBrowser() error {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return fmt.Errorf("failed to init cookie jar: %w", err)
	}

	a.browser = &http.Client{
		Jar:       jar,
		Transport: &http.Transport{TLSClientConfig: a.tlsConfig},
	}

	return nil
}

func CreateDefaultConfig(hubAuthURL string) *LoginConfig {
	return &LoginConfig{
		HubAuthHydraAdminURL:            hubAuthHydraAdminURL,
		HubAuthOIDCProviderURL:          hubAuthOIDCProviderURL,
		HubAuthOIDCProviderSelectionURL: hubAuthURL + hubAuthOIDCProviderSelectionPath,
		HubAuthSelectOIDCProviderURL:    hubAuthURL + hubAuthSelectOIDCProviderPath,
		LoginURL:                        mockLoginURL,
		AuthenticationURL:               mockAuthenticationURL,
		ConsentURL:                      mockConsentURL,
		AuthorizationURL:                mockAuthorizationURL,
		OIDCProviderName:                mockOIDCProviderName,
	}
}
