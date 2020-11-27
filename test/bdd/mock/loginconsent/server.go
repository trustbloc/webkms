/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/ory/hydra-client-go/client"
	"github.com/ory/hydra-client-go/client/admin"
	"github.com/ory/hydra-client-go/models"
	"github.com/trustbloc/edge-core/pkg/storage"
)

const (
	loginChallengeCookieName   = "bdd_test_cookie_login_challenge"
	consentChallengeCookieName = "bdd_test_cookie_consent_challenge"
)

func newServer(c *config) *server {
	s := &server{
		conf:   c,
		router: mux.NewRouter(),
		hydra: client.NewHTTPClientWithConfig(
			nil,
			&client.TransportConfig{
				Host:     c.hydraAdminURL.Host,
				BasePath: c.hydraAdminURL.Path,
				Schemes:  []string{c.hydraAdminURL.Scheme},
			},
		).Admin,
		httpClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: c.tlsConfig,
			},
		},
		store: c.store,
	}

	mockRouter := s.router.PathPrefix("/mock").Subrouter()
	mockRouter.HandleFunc("/login", s.loginHandler).Methods(http.MethodGet)
	mockRouter.HandleFunc("/authn", s.userAuthNHandler).Methods(http.MethodPost)
	mockRouter.HandleFunc("/consent", s.consentHandler).Methods(http.MethodGet)
	mockRouter.HandleFunc("/authz", s.userAuthZHandler).Methods(http.MethodPost)

	return s
}

type server struct {
	conf       *config
	router     *mux.Router
	hydra      admin.ClientService
	httpClient *http.Client
	store      storage.Store
}

type testConfig struct {
	Request *AuthConfigRequest
}

type AuthConfigRequest struct {
	Sub  string `json:"sub"`
	Fail bool   `json:"fail,omitempty"`
}

type ConsentConfigRequest struct {
	UserClaims *UserClaims `json:"user_claims,omitempty"`
	Fail       bool        `json:"fail,omitempty"`
}

// BDD tests can configure
type UserClaims struct {
	Sub        string `json:"sub"`
	Name       string `json:"name"`
	GivenName  string `json:"given_name"`
	FamilyName string `json:"family_name"`
	Email      string `json:"email"`
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

func (s *server) loginHandler(w http.ResponseWriter, r *http.Request) {
	logger.Infof("handling request: %s", r.URL.String())

	challenge := r.URL.Query().Get("login_challenge")
	if challenge == "" {
		logger.Errorf("missing login_challenge")

		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:  loginChallengeCookieName,
		Value: challenge,
	})

	_, err := w.Write([]byte("mock login UI"))
	if err != nil {
		logger.Errorf("failed to write imaginary UI: %s", err.Error())

		return
	}

	logger.Infof("rendered mock login UI in response to request %s", r.URL.String())
}

func (s *server) userAuthNHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(loginChallengeCookieName)
	if err != nil {
		logger.Errorf("failed to fetch cookie %s: %s", loginChallengeCookieName, err.Error())

		return
	}

	request := &AuthConfigRequest{}

	err = json.NewDecoder(r.Body).Decode(request)
	if err != nil {
		logger.Errorf("failed to decode auth request: %s", err.Error())

		return
	}

	if request.Fail {
		reject := admin.NewRejectLoginRequestParams()
		reject.SetContext(r.Context())
		reject.SetLoginChallenge(cookie.Value)
		reject.SetHTTPClient(s.httpClient)

		rejected, err := s.hydra.RejectLoginRequest(reject)
		if err != nil {
			logger.Errorf("failed to reject login request at hydra: %s", err.Error())

			return
		}

		redirectURL := *rejected.Payload.RedirectTo

		http.Redirect(w, r, redirectURL, http.StatusFound)
		logger.Infof("rejected login request; redirected to: %s", redirectURL)

		return
	}

	bits, err := json.Marshal(&testConfig{
		Request: request,
	})
	if err != nil {
		logger.Errorf("failed to marshal test config: %s", err.Error())

		return
	}

	err = s.store.Put(request.Sub, bits)
	if err != nil {
		logger.Errorf("failed to save test config: %s", err.Error())

		return
	}

	accept := admin.NewAcceptLoginRequestParams()
	accept.SetContext(r.Context())
	accept.SetLoginChallenge(cookie.Value)
	accept.SetBody(&models.AcceptLoginRequest{
		Subject: &request.Sub,
	})
	accept.SetHTTPClient(s.httpClient)

	response, err := s.hydra.AcceptLoginRequest(accept)
	if err != nil {
		logger.Errorf("failed to accept hydra login request: %s", err.Error())

		return
	}

	redirectURL := *response.Payload.RedirectTo

	http.Redirect(w, r, redirectURL, http.StatusFound)
	logger.Infof("redirected to: %s", redirectURL)
}

func (s *server) consentHandler(w http.ResponseWriter, r *http.Request) {
	logger.Infof("handling request: %s", r.URL.String())

	challenge := r.URL.Query().Get("consent_challenge")
	if challenge == "" {
		logger.Errorf("missing consent_challenge")

		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:  consentChallengeCookieName,
		Value: challenge,
	})

	_, err := w.Write([]byte("mock consent UI"))
	if err != nil {
		logger.Errorf("failed to write imaginary UI: %s", err.Error())

		return
	}

	logger.Infof("rendered mock consent UI in response to request %s", r.URL.String())
}

func (s *server) userAuthZHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(consentChallengeCookieName)
	if err != nil {
		logger.Errorf("failed to fetch cookie %s: %s", consentChallengeCookieName, err.Error())

		return
	}

	request := &ConsentConfigRequest{}

	err = json.NewDecoder(r.Body).Decode(request)
	if err != nil {
		logger.Errorf("failed to decode user consent config request: %s", err.Error())

		return
	}

	params := admin.NewGetConsentRequestParams()

	params.SetContext(r.Context())
	params.SetHTTPClient(s.httpClient)
	params.SetConsentChallenge(cookie.Value)

	consent, err := s.hydra.GetConsentRequest(params)
	if err != nil {
		logger.Errorf("failed to get hydra consent request: %s", err.Error())

		return
	}

	bits, err := s.store.Get(consent.Payload.Subject)
	if err != nil {
		logger.Errorf("failed to fetch test config for sub=%s: %s", consent.Payload.Subject, err.Error())

		return
	}

	test := &testConfig{}

	err = json.Unmarshal(bits, test)
	if err != nil {
		logger.Errorf("failed to unmarshal user data %s: %s", bits, err.Error())

		return
	}

	if request.Fail {
		reject := admin.NewRejectConsentRequestParams()
		reject.SetContext(r.Context())
		reject.SetHTTPClient(s.httpClient)
		reject.SetConsentChallenge(cookie.Value)

		rejected, err := s.hydra.RejectConsentRequest(reject)
		if err != nil {
			logger.Errorf("failed to reject consent request at hydra: %s", err.Error())

			return
		}

		redirectURL := *rejected.Payload.RedirectTo

		http.Redirect(w, r, redirectURL, http.StatusFound)
		logger.Infof("user did not consent; redirected to %s", redirectURL)

		return
	}

	accept := admin.NewAcceptConsentRequestParams()
	accept.SetContext(r.Context())
	accept.SetConsentChallenge(*consent.Payload.Challenge)
	accept.SetBody(&models.AcceptConsentRequest{
		GrantAccessTokenAudience: consent.Payload.RequestedAccessTokenAudience,
		GrantScope:               consent.Payload.RequestedScope,
		HandledAt:                models.NullTime(time.Now()),
		Session: &models.ConsentRequestSession{
			IDToken: request.UserClaims,
		},
	})
	accept.SetHTTPClient(s.httpClient)

	accepted, err := s.hydra.AcceptConsentRequest(accept)
	if err != nil {
		logger.Errorf("failed to accept hydra consent request: %s", err.Error())

		return
	}

	redirectURL := *accepted.Payload.RedirectTo

	http.Redirect(w, r, redirectURL, http.StatusFound)
	logger.Infof("user authorized; redirected to: %s", redirectURL)
}
