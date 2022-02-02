/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mw

import (
	"context"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/piprate/json-gold/ld"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/zcapld"

	"github.com/trustbloc/kms/pkg/metrics"
)

// ZCAPConfig is a configuration for zcapld middleware.
type ZCAPConfig struct {
	AuthService          authService
	JSONLDLoader         ld.DocumentLoader
	Logger               log.Logger
	VDRResolver          zcapld.VDRResolver
	BaseResourceURL      string
	ResourceIDQueryParam string
}

type authService interface {
	CreateDIDKey(context.Context) (string, error)
	NewCapability(ctx context.Context, options ...zcapld.CapabilityOption) (*zcapld.Capability, error)
	KMS() kms.KeyManager
	Crypto() crypto.Crypto
	Resolve(string) (*zcapld.Capability, error)
}

type namer interface {
	GetName() string
}

type muxNamer struct{}

func (m *muxNamer) GetName(r *http.Request) namer {
	return mux.CurrentRoute(r)
}

type mwHandler struct {
	next                 http.Handler
	zcaps                zcapld.CapabilityResolver
	keys                 kms.KeyManager
	crpto                crypto.Crypto
	jsonLDLoader         ld.DocumentLoader
	logger               log.Logger
	routeFunc            func(*http.Request) namer
	vdrResolver          zcapld.VDRResolver
	baseResourceURL      string
	resourceIDQueryParam string
	handlerAction        string
}

// ZCAPLDMiddleware returns the ZCAPLD middleware that authorizes requests.
func ZCAPLDMiddleware(c *ZCAPConfig, handlerAction string) mux.MiddlewareFunc {
	return func(h http.Handler) http.Handler {
		return &mwHandler{
			next:                 h,
			zcaps:                c.AuthService,
			keys:                 c.AuthService.KMS(),
			crpto:                c.AuthService.Crypto(),
			jsonLDLoader:         c.JSONLDLoader,
			logger:               c.Logger,
			routeFunc:            (&muxNamer{}).GetName,
			vdrResolver:          c.VDRResolver,
			baseResourceURL:      c.BaseResourceURL,
			resourceIDQueryParam: c.ResourceIDQueryParam,
			handlerAction:        handlerAction,
		}
	}
}

func (h *mwHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.logger.Debugf("handling request: %s %s", r.Method, r.URL.String())

	if h.handlerAction == "" {
		h.logger.Errorf("zcap middleware failed to determine route action")
		http.Error(w, "bad request", http.StatusBadRequest)

		return
	}

	getStartTime := time.Now()

	resource := h.baseResourceURL + "/" + mux.Vars(r)[h.resourceIDQueryParam]

	expectations := &zcapld.InvocationExpectations{
		Target:         resource,
		RootCapability: resource,
		Action:         h.handlerAction,
	}

	// TODO make KeyResolver configurable
	// TODO make signature suites configurable
	zcapld.NewHTTPSigAuthHandler(
		&zcapld.HTTPSigAuthConfig{
			CapabilityResolver: h.zcaps,
			KeyResolver:        zcapld.NewDIDKeyResolver(h.vdrResolver),
			VDRResolver:        h.vdrResolver,
			VerifierOptions: []zcapld.VerificationOption{
				zcapld.WithSignatureSuites(
					ed25519signature2018.New(suite.WithVerifier(ed25519signature2018.NewPublicKeyVerifier())),
				),
				zcapld.WithLDDocumentLoaders(h.jsonLDLoader),
			},
			Secrets:     &zcapld.AriesDIDKeySecrets{},
			ErrConsumer: h.logError,
			KMS:         h.keys,
			Crypto:      h.crpto,
		},
		expectations,
		func(w http.ResponseWriter, r *http.Request) {
			metrics.Get().ZCAPLDTime(time.Since(getStartTime))
			h.next.ServeHTTP(w, r)
		},
	).ServeHTTP(w, r)

	h.logger.Debugf("finished handling request: %s", r.URL.String())
}

func (h *mwHandler) logError(err error) {
	h.logger.Errorf("unauthorized capability invocation: %s", err.Error())
}
