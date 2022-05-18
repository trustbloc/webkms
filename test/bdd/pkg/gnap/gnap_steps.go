/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gnap

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"text/template"

	"github.com/cucumber/godog"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/igor-pavlenko/httpsignatures-go"
	"github.com/tidwall/gjson"
	"github.com/trustbloc/auth/component/gnap/as"
	"github.com/trustbloc/auth/spi/gnap"
	"github.com/trustbloc/auth/spi/gnap/proof/httpsig"

	bddcontext "github.com/trustbloc/kms/test/bdd/pkg/context"
	"github.com/trustbloc/kms/test/bdd/pkg/internal/httputil"
	"github.com/trustbloc/kms/test/bdd/pkg/internal/vdrutil"
)

const (
	httpSigAlgorithm = "ECDSA-SHA256"
	proofType        = "httpsig"
)

const (
	authServerURL           = "https://auth.trustbloc.local:8070"
	oidcProviderSelectorURL = authServerURL + "/oidc/login"
	mockOIDCProviderName    = "mockbank1" // oidc-config/providers.yaml
	mockClientFinishURI     = "https://mock.client.example.com/"
)

// DIDOwner defines parameters of a DID owner.
type DIDOwner struct {
	DID        string
	KeyID      string
	PrivateKey *jwk.JWK
}

// Steps defines context for the GNAP steps.
type Steps struct {
	bddContext         *bddcontext.BDDContext
	httpClient         *http.Client
	browser            *http.Client
	vdr                vdrapi.Registry
	users              map[string]*DIDOwner
	gnapToken          string
	responseStatus     string
	responseStatusCode int
	responseBody       []byte
}

func NewSteps(tlsConfig *tls.Config) (*Steps, error) {
	httpClient := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("init cookie jar: %w", err)
	}

	browser := &http.Client{
		Jar:       jar,
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}

	vdr, err := vdrutil.CreateVDR(httpClient)
	if err != nil {
		return nil, err
	}

	return &Steps{
		httpClient: httpClient,
		browser:    browser,
		vdr:        vdr,
		users:      make(map[string]*DIDOwner),
	}, nil
}

// SetContext sets a fresh context for every scenario.
func (s *Steps) SetContext(ctx *bddcontext.BDDContext) {
	s.bddContext = ctx
}

// RegisterSteps defines scenario steps.
func (s *Steps) RegisterSteps(sc *godog.ScenarioContext) {
	sc.Step(`^"([^"]*)" has been granted with GNAP access token to Key Server$`, s.grantGNAPToken)
	sc.Step(`^an HTTP POST with GNAP access token and "([^"]*)" headers signed by "([^"]*)" is sent to "([^"]*)"$`, s.httpPost) //nolint:lll
	sc.Step(`^response status is "([^"]*)"$`, s.checkResponseStatus)
	sc.Step(`^response contains non-empty "([^"]*)"$`, s.checkNonEmptyResponseValue)
}

func (s *Steps) grantGNAPToken(userName string) error {
	user, ok := s.users[userName]
	if !ok {
		u, err := s.createDIDOwner()
		if err != nil {
			return fmt.Errorf("create user: %w", err)
		}

		user = u
		s.users[userName] = user
	}

	gnapClient, err := as.NewClient(&httpsig.Signer{SigningKey: user.PrivateKey}, s.httpClient, authServerURL)
	if err != nil {
		return fmt.Errorf("create gnap client: %w", err)
	}

	publicJWK := &jwk.JWK{
		JSONWebKey: user.PrivateKey.Public(),
		Kty:        "EC",
		Crv:        "P-256",
	}

	req := &gnap.AuthRequest{
		Client: &gnap.RequestClient{
			Key: &gnap.ClientKey{
				Proof: proofType,
				JWK:   *publicJWK,
			},
		},
		AccessToken: []*gnap.TokenRequest{
			{
				Access: []gnap.TokenAccess{
					{
						IsReference: true,
						Ref:         "example-token-type",
					},
				},
			},
		},
		Interact: &gnap.RequestInteract{
			Start: []string{"redirect"},
			Finish: gnap.RequestFinish{
				Method: "redirect",
				URI:    mockClientFinishURI,
			},
		},
	}

	authResp, err := gnapClient.RequestAccess(req)
	if err != nil {
		return fmt.Errorf("request gnap access: %w", err)
	}

	interactURL, err := url.Parse(authResp.Interact.Redirect)
	if err != nil {
		return fmt.Errorf("parse interact url: %w", err)
	}

	txnID := interactURL.Query().Get("txnID")

	// redirect to interact url
	resp, err := s.browser.Get(authResp.Interact.Redirect)
	if err != nil {
		return fmt.Errorf("redirect to interact url: %w", err)
	}

	defer resp.Body.Close() //nolint:errcheck

	// select provider
	requestURL := fmt.Sprintf("%s?provider=%s&txnID=%s", oidcProviderSelectorURL, mockOIDCProviderName, txnID)

	s.browser.CheckRedirect = func(req *http.Request, via []*http.Request) error { // do not follow redirects
		return http.ErrUseLastResponse
	}

	resp, err = s.browser.Get(requestURL)
	if err != nil {
		return fmt.Errorf("redirect to OIDC provider (%s): %w", requestURL, err)
	}

	requestURL = resp.Header.Get("Location")

	resp, err = s.browser.Get(requestURL)
	if err != nil {
		return fmt.Errorf("redirect to OIDC provider (%s): %w", requestURL, err)
	}

	requestURL = resp.Header.Get("Location")

	resp, err = s.browser.Get(requestURL)
	if err != nil {
		return fmt.Errorf("redirect to login (%s): %w", requestURL, err)
	}

	// login to third-party oidc
	resp, err = s.browser.Post(resp.Request.URL.String(), "", nil)
	if err != nil {
		return fmt.Errorf("login to third-party oidc: %w", err)
	}

	requestURL = resp.Header.Get("Location")

	resp, err = s.browser.Get(requestURL)
	if err != nil {
		return fmt.Errorf("redirect to post-login oauth (%s): %w", requestURL, err)
	}

	requestURL = resp.Header.Get("Location")

	resp, err = s.browser.Get(requestURL)
	if err != nil {
		return fmt.Errorf("redirect to consent (%s): %w", requestURL, err)
	}

	requestURL = resp.Header.Get("Location")

	resp, err = s.browser.Get(requestURL)
	if err != nil {
		return fmt.Errorf("redirect to post-consent oauth (%s): %w", requestURL, err)
	}

	requestURL = resp.Header.Get("Location")

	resp, err = s.browser.Get(requestURL)
	if err != nil {
		return fmt.Errorf("redirect to auth callback (%s): %w", requestURL, err)
	}

	clientRedirect := resp.Header.Get("Location")

	crURL, err := url.Parse(clientRedirect)
	if err != nil {
		return fmt.Errorf("parse client redirect url: %w", err)
	}

	interactRef := crURL.Query().Get("interact_ref")

	continueReq := &gnap.ContinueRequest{
		InteractRef: interactRef,
	}

	continueResp, err := gnapClient.Continue(continueReq, authResp.Continue.AccessToken.Value)
	if err != nil {
		return fmt.Errorf("call continue request: %w", err)
	}

	s.gnapToken = continueResp.AccessToken[0].Value

	return nil
}

func (s *Steps) createDIDOwner() (*DIDOwner, error) {
	doc, pk, err := vdrutil.CreateDIDDoc(s.vdr)
	if err != nil {
		return nil, fmt.Errorf("create did doc: %w", err)
	}

	_, err = vdrutil.ResolveDID(s.vdr, doc.ID, 10) //nolint:gomnd
	if err != nil {
		return nil, fmt.Errorf("resolve did: %w", err)
	}

	return &DIDOwner{
		DID:        doc.ID,
		KeyID:      doc.Authentication[0].VerificationMethod.ID,
		PrivateKey: pk,
	}, nil
}

func (s *Steps) httpPost(headers, userName, url string, bodyTemplate *godog.DocString) error {
	user, ok := s.users[userName]
	if !ok {
		return fmt.Errorf("user %q not defined", userName)
	}

	signer := &requestSigner{
		Headers:    strings.Split(headers, ","),
		KeyID:      user.KeyID,
		PrivateKey: user.PrivateKey.Key.(*ecdsa.PrivateKey),
	}

	return s.httpDo(context.Background(), http.MethodPost, url, bodyTemplate, httputil.WithSigner(signer))
}

func (s *Steps) httpDo(ctx context.Context, method, url string, bodyTemplate *godog.DocString,
	opts ...httputil.Opt) error {
	opts = append(opts, httputil.WithHTTPClient(s.httpClient), httputil.WithMethod(method),
		httputil.WithGNAPToken(s.gnapToken))

	if bodyTemplate != nil {
		t, err := template.New("body").Parse(bodyTemplate.Content)
		if err != nil {
			return fmt.Errorf("parse body template: %w", err)
		}

		var buf bytes.Buffer

		err = t.Execute(&buf, s)
		if err != nil {
			return fmt.Errorf("execute body template: %w", err)
		}

		opts = append(opts, httputil.WithBody(buf.Bytes()))
	}

	r, err := httputil.DoRequest(ctx, url, opts...)
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}

	s.responseStatus = r.Status
	s.responseStatusCode = r.StatusCode
	s.responseBody = r.Body

	return nil
}

func (s *Steps) checkResponseStatus(status string) error {
	if s.responseStatus != status {
		return fmt.Errorf("expected %q, got %q", status, s.responseStatus)
	}

	return nil
}

func (s *Steps) checkNonEmptyResponseValue(path string) error {
	val := gjson.Get(string(s.responseBody), path)

	if val.Str == "" {
		return fmt.Errorf("got empty value")
	}

	return nil
}

type requestSigner struct {
	Headers    []string
	KeyID      string
	PrivateKey *ecdsa.PrivateKey
}

// Sign signs HTTP headers in HTTP Message Signatures auth method.
func (s *requestSigner) Sign(req *http.Request) error {
	hs := httpsignatures.NewHTTPSignatures(&secretRetriever{KeyID: s.KeyID, PrivateKey: s.PrivateKey})
	hs.SetDefaultSignatureHeaders(s.Headers)

	if err := hs.Sign(s.KeyID, req); err != nil {
		return fmt.Errorf("sign request: %w", err)
	}

	return nil
}

type secretRetriever struct {
	KeyID      string
	PrivateKey *ecdsa.PrivateKey
}

// Get returns a secret with the key ID and pem-encoded private key.
func (r *secretRetriever) Get(_ string) (httpsignatures.Secret, error) {
	b, err := x509.MarshalPKCS8PrivateKey(r.PrivateKey)
	if err != nil {
		return httpsignatures.Secret{}, fmt.Errorf("marshal private key: %w", err)
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: b,
	})

	return httpsignatures.Secret{
		KeyID:      r.KeyID,
		Algorithm:  httpSigAlgorithm,
		PrivateKey: string(privateKeyPEM),
	}, nil
}

// GetDID is a helper function used in template to get DID of the user.
func (s *Steps) GetDID(userName string) string {
	return s.users[userName].DID
}
