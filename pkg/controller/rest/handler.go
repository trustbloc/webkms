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
	Action() string
	ZCAPProtect() bool
	Method() string
	Handle() http.HandlerFunc
}

// NewHTTPHandler returns an instance of HTTPHandler that shouldn't be zcap protected.
func NewHTTPHandler(path, method string, handle http.HandlerFunc, action string, zcapProtected bool) *HTTPHandler {
	return &HTTPHandler{path: path, action: action, zcapProtected: zcapProtected, method: method, handle: handle}
}

// HTTPHandler is an HTTP handler for the given path and method.
type HTTPHandler struct {
	path          string
	action        string
	zcapProtected bool
	method        string
	handle        http.HandlerFunc
}

// Path returns HTTP request path.
func (h *HTTPHandler) Path() string {
	return h.path
}

// Action returns action associated with request path.
func (h *HTTPHandler) Action() string {
	return h.action
}

// ZCAPProtect indicates should the path be protected by zcap.
func (h *HTTPHandler) ZCAPProtect() bool {
	return h.zcapProtected
}

// Method returns HTTP request method type.
func (h *HTTPHandler) Method() string {
	return h.method
}

// Handle returns HTTP request handler func.
func (h *HTTPHandler) Handle() http.HandlerFunc {
	return h.handle
}
