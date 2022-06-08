/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination gomocks_test.go -package oauthmw_test . HTTPHandler

package oauthmw

import (
	"net/http"
	"strings"
)

// Middleware is an OAuth2 auth middleware.
type Middleware struct{}

// HTTPHandler is an alias for http.Handler (used by GoMock to generate a mock).
type HTTPHandler = http.Handler

// Accept accepts requests with Bearer token in Authorization header. Token introspection is done by third-party
// service, e.g. Oathkeeper reverse proxy.
func (mw *Middleware) Accept(req *http.Request) bool {
	if v, ok := req.Header["Authorization"]; ok {
		for _, h := range v {
			if strings.Contains(h, "Bearer") {
				return true
			}
		}
	}

	return false
}

// Middleware returns middleware func.
func (mw *Middleware) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return &oauthHandler{
			next: next,
		}
	}
}

type oauthHandler struct {
	next http.Handler
}

// ServeHTTP calls the next handler assuming that authorization was already done by third-party service.
func (h *oauthHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	h.next.ServeHTTP(w, req)
}
