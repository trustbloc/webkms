/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rest

import "net/http"

var _ Handler = (*HTTPHandler)(nil)

// Handler represents an HTTP handler for controller API endpoint.
type Handler interface {
	Path() string
	Method() string
	Handler() http.HandlerFunc
	Action() string
	Auth() AuthMethod
}

// NewHTTPHandler returns a configured instance of HTTPHandler.
func NewHTTPHandler(path, method string, handler http.HandlerFunc, action string, auth AuthMethod) *HTTPHandler {
	return &HTTPHandler{path: path, method: method, handler: handler, action: action, auth: auth}
}

// AuthMethod represents an authorization method.
type AuthMethod int

const (
	// AuthNone defines that auth is not handled by the service.
	AuthNone AuthMethod = 1 << iota
	// AuthZCAP defines ZCAP as a supported auth method for the handler.
	AuthZCAP
	// AuthGNAP defines GNAP as a supported auth method for the handler.
	AuthGNAP
)

// HasFlag checks if the given auth method is set.
func (a AuthMethod) HasFlag(flag AuthMethod) bool {
	return a&flag != 0
}

// HTTPHandler is an HTTP handler for the given path and method.
type HTTPHandler struct {
	path    string
	method  string
	handler http.HandlerFunc
	action  string
	auth    AuthMethod
}

// Path returns an HTTP request path.
func (h *HTTPHandler) Path() string {
	return h.path
}

// Method returns an HTTP request method.
func (h *HTTPHandler) Method() string {
	return h.method
}

// Handler returns an HTTP request handler func.
func (h *HTTPHandler) Handler() http.HandlerFunc {
	return h.handler
}

// Action returns an action associated with the request path.
func (h *HTTPHandler) Action() string {
	return h.action
}

// Auth returns supported authorization method.
func (h *HTTPHandler) Auth() AuthMethod {
	return h.auth
}
