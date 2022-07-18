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
	disableHTTPSIG bool
}

// NewMiddleware validates GNAP auth fields are not empty and returns a complete middleware instance.
func NewMiddleware(client gnapRSClient, rsPubKey *jwk.JWK, createVerifier createVerifierFunc,
	disableHTTPSIG bool) (*Middleware, error) {
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
		disableHTTPSIG: disableHTTPSIG,
	}, nil
}

// HTTPHandler is an HTTP handler (used by GoMock to generate a mock).
type HTTPHandler interface {
	http.Handler
}

// Accept checks if the request can be handled by the GNAP middleware.
func (mw *Middleware) Accept(req *http.Request) bool {
	v := req.Header.Values("Authorization")
	for _, h := range v {
		if strings.Contains(h, gnapToken) {
			logger.Debugf("Accept: %v is true", v)

			return true
		}
	}

	return false
}

// Middleware returns middleware func.
func (mw *Middleware) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return &gnapHandler{
			client: mw.client,
			clientKey: &gnap.ClientKey{
				Proof: proofType,
				JWK:   *mw.rsPubKey,
			},
			createVerifier: mw.createVerifier,
			disableHTTPSIG: mw.disableHTTPSIG,
			next:           next,
		}
	}
}

type gnapHandler struct {
	client         gnapRSClient
	clientKey      *gnap.ClientKey
	next           http.Handler
	createVerifier createVerifierFunc
	disableHTTPSIG bool
}

// ServeHTTP authorizes an incoming HTTP request using GNAP.
func (h *gnapHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
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
