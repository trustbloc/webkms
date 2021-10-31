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
	Handle() http.HandlerFunc
}

// NewHTTPHandler returns an instance of HTTPHandler.
func NewHTTPHandler(path, method string, handle http.HandlerFunc) *HTTPHandler {
	return &HTTPHandler{path: path, method: method, handle: handle}
}

// HTTPHandler is an HTTP handler for the given path and method.
type HTTPHandler struct {
	path   string
	method string
	handle http.HandlerFunc
}

// Path returns HTTP request path.
func (h *HTTPHandler) Path() string {
	return h.path
}

// Method returns HTTP request method type.
func (h *HTTPHandler) Method() string {
	return h.method
}

// Handle returns HTTP request handler func.
func (h *HTTPHandler) Handle() http.HandlerFunc {
	return h.handle
}
