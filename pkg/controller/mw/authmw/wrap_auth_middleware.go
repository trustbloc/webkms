/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination gomocks_test.go -package authmw_test . HTTPHandler,Middleware

package authmw

import "net/http"

// Middleware represents an auth middleware that can handle authorization for the given HTTP request.
type Middleware interface {
	Accept(req *http.Request) bool
	Middleware() func(http.Handler) http.Handler
}

// HTTPHandler is an alias for http.Handler (used by GoMock to generate a mock).
type HTTPHandler = http.Handler

// Wrap returns middleware that combines other auth middlewares.
func Wrap(mw ...Middleware) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return &authHandler{
			middlewares: mw,
			next:        next,
		}
	}
}

type authHandler struct {
	middlewares []Middleware
	next        http.Handler
}

// ServeHTTP authorizes incoming HTTP requests.
func (h *authHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	for _, mw := range h.middlewares {
		if mw.Accept(req) {
			mw.Middleware()(h.next).ServeHTTP(w, req)

			return
		}
	}

	http.Error(w, "unauthorized", http.StatusUnauthorized)
}
