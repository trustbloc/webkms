/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package zcapmw

//go:generate mockgen -destination gomocks_test.go -package zcapmw . DocumentLoader,CapabilityResolver,VDRResolver

import (
	"context"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/piprate/json-gold/ld"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/zcapld"

	"github.com/trustbloc/kms/pkg/metrics"
)

// DocumentLoader is an alias for ld.DocumentLoader.
type DocumentLoader = ld.DocumentLoader

// CapabilityResolver is an alias for zcapld.CapabilityResolver.
type CapabilityResolver = zcapld.CapabilityResolver

// VDRResolver is an alias for zcapld.VDRResolver.
type VDRResolver = zcapld.VDRResolver

type authService interface {
	NewCapability(ctx context.Context, options ...zcapld.CapabilityOption) (*zcapld.Capability, error)
	KMS() kms.KeyManager
	Crypto() crypto.Crypto
	Resolve(string) (*zcapld.Capability, error)
}

// ZCAPConfig is a configuration for zcapld middleware.
type ZCAPConfig struct {
	AuthService          authService
	JSONLDLoader         ld.DocumentLoader
	Logger               log.Logger
	VDRResolver          zcapld.VDRResolver
	BaseResourceURL      string
	ResourceIDQueryParam string
}

// Middleware returns middleware func.
func Middleware(config *ZCAPConfig, action string, next http.Handler) http.Handler {
	return &mwHandler{
		next:                 next,
		zcaps:                &capabilityResolverMetrics{wrapped: config.AuthService},
		keys:                 config.AuthService.KMS(),
		crpto:                config.AuthService.Crypto(),
		jsonLDLoader:         &documentLoaderMetrics{wrapped: config.JSONLDLoader},
		logger:               config.Logger,
		routeFunc:            (&muxNamer{}).GetName,
		vdrResolver:          &vdrResolverMetrics{wrapped: config.VDRResolver},
		baseResourceURL:      config.BaseResourceURL,
		resourceIDQueryParam: config.ResourceIDQueryParam,
		handlerAction:        action,
	}
}

type namer interface {
	GetName() string
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

type muxNamer struct{}

func (m *muxNamer) GetName(r *http.Request) namer {
	return mux.CurrentRoute(r)
}

type capabilityResolverMetrics struct {
	wrapped zcapld.CapabilityResolver
}

func (c *capabilityResolverMetrics) Resolve(uri string) (*zcapld.Capability, error) {
	getStartTime := time.Now()

	cm, err := c.wrapped.Resolve(uri)

	metrics.Get().ZCAPLDCapabilityResolveTime(time.Since(getStartTime))

	return cm, err
}

type documentLoaderMetrics struct {
	wrapped ld.DocumentLoader
}

func (w *documentLoaderMetrics) LoadDocument(u string) (*ld.RemoteDocument, error) {
	getStartTime := time.Now()

	d, err := w.wrapped.LoadDocument(u)

	metrics.Get().ZCAPLDLoadDocumentTime(time.Since(getStartTime))

	return d, err
}

type vdrResolverMetrics struct {
	wrapped zcapld.VDRResolver
}

func (w *vdrResolverMetrics) Resolve(didStr string, opts ...vdr.DIDMethodOption) (*did.DocResolution, error) {
	getStartTime := time.Now()

	d, err := w.wrapped.Resolve(didStr, opts...)

	metrics.Get().ZCAPLDVDRResolveTime(time.Since(getStartTime))

	return d, err
}
