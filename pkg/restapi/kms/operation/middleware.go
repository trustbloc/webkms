/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/piprate/json-gold/ld"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/zcapld"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/label"
)

var tracer = otel.Tracer("kms/operation") //nolint:gochecknoglobals // ignore

// ZCAPLDMiddleware returns the ZCAPLD middleware that authorizes requests.
func (o *Operation) ZCAPLDMiddleware(h http.Handler) http.Handler {
	return &mwHandler{
		next:         h,
		zcaps:        o.authService,
		keys:         o.authService.KMS(),
		crpto:        o.authService.Crypto(),
		jsonLDLoader: o.jsonLDLoader,
		logger:       o.logger,
		routeFunc:    (&muxNamer{}).GetName,
		baseURL:      o.baseURL,
	}
}

type namer interface {
	GetName() string
}

type muxNamer struct {
}

func (m *muxNamer) GetName(r *http.Request) namer {
	return mux.CurrentRoute(r)
}

type mwHandler struct {
	next         http.Handler
	zcaps        zcapld.CapabilityResolver
	keys         kms.KeyManager
	crpto        crypto.Crypto
	jsonLDLoader ld.DocumentLoader
	logger       log.Logger
	routeFunc    func(*http.Request) namer
	baseURL      string
}

func (h *mwHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) { //nolint:funlen // TODO refactor
	ctx, span := tracer.Start(r.Context(), "ZCAPLDMiddleware")
	defer span.End()

	span.SetAttributes(label.String("http.host", r.Host))
	span.SetAttributes(label.String("http.method", r.Method))
	span.SetAttributes(label.String("http.url", r.URL.String()))

	h.logger.Debugf("handling request: %s", r.URL.String())

	// this one is protected with OAuth2
	if h.routeFunc(r).GetName() == keystoresEndpoint {
		h.next.ServeHTTP(w, r.WithContext(ctx))

		span.AddEvent(fmt.Sprintf("handling request %q completed", r.URL.String()))

		return
	}

	resource := keystoreLocation(h.baseURL, mux.Vars(r)[keystoreIDQueryParam])

	expectations := &zcapld.InvocationExpectations{
		Target:         resource,
		RootCapability: resource,
	}

	var err error

	expectations.Action, err = expectedAction(h.routeFunc(r))
	if err != nil {
		h.logger.Errorf("zcap middleware failed to determine the expected action: %s", err.Error())
		http.Error(w, "bad request", http.StatusBadRequest)

		return
	}

	span.AddEvent("populating cache for JSON-LD documents completed")

	// TODO make KeyResolver configurable
	// TODO make signature suites configurable
	zcapld.NewHTTPSigAuthHandler(
		&zcapld.HTTPSigAuthConfig{
			CapabilityResolver: h.zcaps,
			KeyResolver:        &zcapld.DIDKeyResolver{},
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
		h.next.ServeHTTP,
	).ServeHTTP(w, r.WithContext(ctx))

	span.AddEvent(fmt.Sprintf("handling request %q completed", r.URL.String()))

	h.logger.Debugf("finished handling request: %s", r.URL.String())
}

func (h *mwHandler) logError(err error) {
	h.logger.Errorf("unauthorized capability invocation: %s", err.Error())
}

func expectedAction(n namer) (string, error) { // nolint:gocyclo // necessary complexity
	var (
		action string
		err    error
	)

	switch n.GetName() {
	case keysEndpoint:
		action = actionCreateKey
	case capabilityEndpoint:
		action = actionStoreCapability
	case exportEndpoint:
		action = actionExportKey
	case importEndpoint:
		action = actionImportKey
	case signEndpoint:
		action = actionSign
	case verifyEndpoint:
		action = actionVerify
	case encryptEndpoint:
		action = actionEncrypt
	case decryptEndpoint:
		action = actionDecrypt
	case computeMACEndpoint:
		action = actionComputeMac
	case verifyMACEndpoint:
		action = actionVerifyMAC
	case wrapEndpoint:
		action = actionWrap
	case unwrapEndpoint:
		action = actionUnwrap
	case easyEndpoint:
		action = actionEasy
	case easyOpenEndpoint:
		action = actionEasyOpen
	case sealOpenEndpoint:
		action = actionSealOpen
	default:
		err = fmt.Errorf("unsupported endpoint: %s", n.GetName())
	}

	return action, err
}

// CapabilityInvocationAction returns the action to invoke on the capability given the request.
func CapabilityInvocationAction(r *http.Request) (string, error) { // nolint:gocyclo // ignore due to switch stmt
	idx := strings.LastIndex(r.URL.Path, "/")
	if idx == -1 {
		return "", fmt.Errorf("invalid path format: %s", r.URL.Path)
	}

	lastPathComponent := r.URL.Path[idx:]

	var (
		action string
		err    error
	)

	switch lastPathComponent {
	case keysPath:
		action = actionCreateKey
	case capabilityPath:
		action = actionStoreCapability
	case exportPath:
		action = actionExportKey
	case importPath:
		action = actionImportKey
	case signPath:
		action = actionSign
	case verifyPath:
		action = actionVerify
	case encryptPath:
		action = actionEncrypt
	case decryptPath:
		action = actionDecrypt
	case computeMACPath:
		action = actionComputeMac
	case verifyMACPath:
		action = actionVerifyMAC
	case wrapPath:
		action = actionWrap
	case unwrapPath:
		action = actionUnwrap
	case easyPath:
		action = actionEasy
	case easyOpenPath:
		action = actionEasyOpen
	case sealOpenPath:
		action = actionSealOpen
	default:
		err = fmt.Errorf("unsupported endpoint: %s", r.URL.Path)
	}

	return action, err
}
