/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//nolint:lll
//go:generate mockgen -destination gomocks_test.go -self_package mocks -package gnapmw_test -source=gnap_middleware.go -mock_names HTTPHandler=MockHTTPHandler,gnapRSClient=MockGNAPRSClient

package gnapmw

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"github.com/trustbloc/auth/spi/gnap"
)

const (
	proofType = "httpsig"
	gnapToken = "GNAP"
)

type gnapRSClient interface {
	Introspect(req *gnap.IntrospectRequest) (*gnap.IntrospectResponse, error)
}

// Middleware is a GNAP auth middleware.
type Middleware struct {
	Client   gnapRSClient
	RSPubKey *jwk.JWK
}

// HTTPHandler is an HTTP handler (used by GoMock to generate a mock).
type HTTPHandler interface {
	http.Handler
}

// Accept checks if the request can be handled by the GNAP middleware.
func (mw *Middleware) Accept(req *http.Request) bool {
	if v, ok := req.Header["Authorization"]; ok {
		for _, h := range v {
			if strings.Contains(h, gnapToken) {
				return true
			}
		}
	}

	return false
}

// Middleware returns middleware func.
func (mw *Middleware) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return &gnapHandler{
			client: mw.Client,
			clientKey: &gnap.ClientKey{
				Proof: proofType,
				JWK:   *mw.RSPubKey,
			},
			next: next,
		}
	}
}

type gnapHandler struct {
	client    gnapRSClient
	clientKey *gnap.ClientKey
	next      http.Handler
}

// ServeHTTP authorizes an incoming HTTP request using GNAP.
func (h *gnapHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	tokenHeader := strings.Split(strings.Trim(req.Header.Get("Authorization"), " "), " ")

	if len(tokenHeader) < 2 || tokenHeader[0] != gnapToken {
		http.Error(w, "unauthorized", http.StatusUnauthorized)

		return
	}

	introspectReq := &gnap.IntrospectRequest{
		ResourceServer: &gnap.RequestClient{
			Key: h.clientKey,
		},
		Proof:       proofType,
		AccessToken: tokenHeader[1],
	}

	resp, err := h.client.Introspect(introspectReq)
	if err != nil {
		http.Error(w, fmt.Sprintf("introspect token: %s", err.Error()), http.StatusInternalServerError)

		return
	}

	if !resp.Active {
		http.Error(w, "unauthorized", http.StatusUnauthorized)

		return
	}

	h.next.ServeHTTP(w, req)
}
