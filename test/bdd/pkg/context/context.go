/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package context

import (
	"crypto/tls"

	tlsutils "github.com/trustbloc/edge-core/pkg/utils/tls"
)

// BDDContext is a global context shared between different test suites in bdd tests.
type BDDContext struct {
	tlsConfig      *tls.Config
	ServerEndpoint string
}

// NewBDDContext creates a new BDDContext.
func NewBDDContext(caCertPath string) (*BDDContext, error) {
	rootCAs, err := tlsutils.GetCertPool(false, []string{caCertPath})
	if err != nil {
		return nil, err
	}

	return &BDDContext{tlsConfig: &tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS12}}, nil
}

// TLSConfig returns a TLS config that BDD context was initialized with.
func (ctx *BDDContext) TLSConfig() *tls.Config {
	return ctx.tlsConfig
}
