/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//nolint:lll
//go:generate mockgen -destination gomocks_test.go -self_package mocks -package gnapmw_test -source=gnap_middleware.go -mock_names HTTPHandler=MockHTTPHandler,gnapRSClient=MockGNAPRSClient,GNAPVerifier=MockGNAPVerifier

package gnapmw

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"github.com/trustbloc/auth/spi/gnap"
	"github.com/trustbloc/edge-core/pkg/log"
)

const (
	proofType = "httpsig"
	gnapToken = "GNAP"
)

var logger = log.New("gnapmw")

type gnapRSClient interface {
	Introspect(req *gnap.IntrospectRequest) (*gnap.IntrospectResponse, error)
}

// Middleware is a GNAP auth middleware.
type Middleware struct {
	client         gnapRSClient
	rsPubKey       *jwk.JWK
	createVerifier createVerifierFunc
	externalURL    string
	disableHTTPSIG bool
}

// NewMiddleware validates GNAP auth fields are not empty and returns a complete middleware instance.
func NewMiddleware(
	client gnapRSClient,
	rsPubKey *jwk.JWK,
	createVerifier createVerifierFunc,
	externalURL string,
	disableHTTPSIG bool,
) (*Middleware, error) {
	if client == nil {
		return nil, errors.New("gnap client is empty")
	}

	if rsPubKey == nil {
		return nil, errors.New("public key is empty")
	}

	if createVerifier == nil {
		return nil, errors.New("createVerifier function is empty")
	}

	return &Middleware{
		client:         client,
		rsPubKey:       rsPubKey,
		createVerifier: createVerifier,
		externalURL:    externalURL,
		disableHTTPSIG: disableHTTPSIG,
	}, nil
}

// HTTPHandler is an HTTP handler (used by GoMock to generate a mock).
type HTTPHandler interface {
	http.Handler
}

// Middleware returns middleware func.
func (mw *Middleware) Middleware(next http.Handler) http.Handler {
	return &gnapHandler{
		client: mw.client,
		clientKey: &gnap.ClientKey{
			Proof: proofType,
			JWK:   *mw.rsPubKey,
		},
		createVerifier: mw.createVerifier,
		disableHTTPSIG: mw.disableHTTPSIG,
		externalURL:    mw.externalURL,
		next:           next,
	}
}

type gnapHandler struct {
	client         gnapRSClient
	clientKey      *gnap.ClientKey
	next           http.Handler
	createVerifier createVerifierFunc
	externalURL    string
	disableHTTPSIG bool
}

// ServeHTTP authorizes an incoming HTTP request using GNAP.
func (h *gnapHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) { //nolint:funlen
	var tokenHeader string

	v := req.Header.Values("Authorization")
	for _, h := range v {
		if strings.Contains(h, gnapToken) {
			tokenHeader = h

			break
		}
	}

	tokenHeaderSplit := strings.Split(strings.Trim(tokenHeader, " "), " ")

	if len(tokenHeaderSplit) < 2 || tokenHeaderSplit[0] != gnapToken {
		http.Error(w, "unauthorized", http.StatusUnauthorized)

		return
	}

	introspectReq := &gnap.IntrospectRequest{
		ResourceServer: &gnap.RequestClient{
			Key: h.clientKey,
		},
		Proof:       proofType,
		AccessToken: tokenHeaderSplit[1],
	}

	resp, err := h.client.Introspect(introspectReq)
	if err != nil {
		http.Error(w, fmt.Sprintf("introspect token: %s", err.Error()), http.StatusInternalServerError)

		return
	}

	if !resp.Active || resp.Key == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)

		return
	}

	// perform HTTPSignature verification if enabled.
	if !h.disableHTTPSIG {
		originalURL := req.URL

		req.URL, err = url.Parse(h.externalURL + req.URL.String())
		if err != nil {
			logger.Warnf("prepending external URL to request URL failed, reverting")

			req.URL = originalURL
		}

		v := h.createVerifier(req)

		err = v.Verify(resp.Key)
		if err != nil {
			logger.Warnf("gnap verification failure %s", err)
			http.Error(w, fmt.Sprintf("verify gnap request: %s", err.Error()), http.StatusUnauthorized)

			return
		}
	}

	h.next.ServeHTTP(w, req)
}

type createVerifierFunc func(req *http.Request) GNAPVerifier

// GNAPVerifier interface to support injecting a verifier in the middleware.
type GNAPVerifier interface {
	Verify(key *gnap.ClientKey) error
}
