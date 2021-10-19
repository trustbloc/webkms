/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb"
	"github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ld"
	arieskms "github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/local"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	ldstore "github.com/hyperledger/aries-framework-go/pkg/store/ld"
	ariesvdr "github.com/hyperledger/aries-framework-go/pkg/vdr"
	vdrkey "github.com/hyperledger/aries-framework-go/pkg/vdr/key"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	jsonld "github.com/piprate/json-gold/ld"
	promclient "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/cors"
	"github.com/spf13/cobra"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/restapi/logspec"
	tlsutils "github.com/trustbloc/edge-core/pkg/utils/tls"
	zcapldcore "github.com/trustbloc/edge-core/pkg/zcapld"

	"github.com/trustbloc/kms/pkg/auth/zcapld"
	"github.com/trustbloc/kms/pkg/kms"
	"github.com/trustbloc/kms/pkg/metrics/prometheus"
	"github.com/trustbloc/kms/pkg/restapi/healthcheck"
	"github.com/trustbloc/kms/pkg/restapi/kms/operation"
	lock "github.com/trustbloc/kms/pkg/secretlock"
	"github.com/trustbloc/kms/pkg/storage/cache"
	"github.com/trustbloc/kms/pkg/storage/edv"
)

const (
	keystorePrimaryKeyURI = "local-lock://keystorekms"
)

// Server represents an HTTP server.
type Server interface {
	ListenAndServe(host, certFile, keyFile string, router http.Handler) error
	Logger() log.Logger
}

// httpServer is the actual Server implementation.
type httpServer struct {
	logger log.Logger
}

// NewHTTPServer returns a new instance of Server.
func NewHTTPServer(logger log.Logger) Server {
	return &httpServer{logger: logger}
}

// ListenAndServe starts the server using the standard HTTP(S) implementation.
func (s *httpServer) ListenAndServe(host, certFile, keyFile string, router http.Handler) error {
	if certFile != "" && keyFile != "" {
		return http.ListenAndServeTLS(host, certFile, keyFile, router)
	}

	return http.ListenAndServe(host, router)
}

// Logger returns a logger instance.
func (s *httpServer) Logger() log.Logger {
	return s.logger
}

// GetStartCmd returns the Cobra start command.
func GetStartCmd(srv Server) *cobra.Command {
	startCmd := createStartCmd(srv)

	createFlags(startCmd)

	return startCmd
}

func createStartCmd(srv Server) *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "Start kms-rest",
		Long:  "Start kms-rest inside the kms",
		RunE: func(cmd *cobra.Command, args []string) error {
			parameters, err := getKmsRestParameters(cmd)
			if err != nil {
				return err
			}

			return startKmsService(parameters, srv)
		},
	}
}

func startKmsService(params *kmsRestParameters, srv Server) error {
	if params.logLevel != "" {
		setLogLevel(params.logLevel, srv)
	}

	router := mux.NewRouter()

	// add health check API handlers
	healthCheckLogger := log.New("kms/healthcheck")
	healthCheckService := healthcheck.New(healthCheckLogger)

	for _, handler := range healthCheckService.GetOperations() {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	// add KMS REST API handlers
	config, err := prepareOperationConfig(params)
	if err != nil {
		return err
	}

	kmsRouter := router.PathPrefix(operation.KMSBasePath).Subrouter()

	if params.hostMetricsURL != "" {
		kmsRouter.Use(prometheus.Middleware)

		go startMetrics(srv, params.hostMetricsURL)
	}

	kmsREST, err := operation.New(config)
	if err != nil {
		return fmt.Errorf("start KMS service: %w", err)
	}

	if params.enableZCAPs {
		kmsRouter.Use(kmsREST.ZCAPLDMiddleware)
	}

	for _, handler := range kmsREST.GetRESTHandlers() {
		kmsRouter.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method()).Name(handler.Name())
	}

	// add logspec API handlers
	for _, handler := range logspec.New().GetOperations() {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	srv.Logger().Infof("Starting KMS on host [%s]", params.hostURL)

	var handler http.Handler
	if params.enableCORS {
		handler = constructCORSHandler(router)
	} else {
		handler = router
	}

	return srv.ListenAndServe(
		params.hostURL,
		params.tlsServeParams.certPath,
		params.tlsServeParams.keyPath,
		handler)
}

func startMetrics(srv Server, metricsHost string) {
	metricsRouter := mux.NewRouter()

	h := promhttp.HandlerFor(promclient.DefaultGatherer,
		promhttp.HandlerOpts{
			EnableOpenMetrics: true,
		},
	)

	metricsRouter.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r)
	})

	srv.Logger().Infof("Starting KMS metrics on host [%s]", metricsHost)

	if err := srv.ListenAndServe(metricsHost, "", "", metricsRouter); err != nil {
		srv.Logger().Fatalf("%v", err)
	}
}

func setLogLevel(level string, srv Server) {
	logLevel, err := log.ParseLevel(level)
	if err != nil {
		srv.Logger().Warnf("%s is not a valid logging level. It must be one of the following: "+
			"critical, error, warning, info, debug. Defaulting to info.", level)

		logLevel = log.INFO
	}

	log.SetLevel("", logLevel)
}

func prepareOperationConfig(params *kmsRestParameters) (*operation.Config, error) {
	storageProvider, err := prepareStorageProvider(params.storageParams)
	if err != nil {
		return nil, err
	}

	primaryKeyLock, err := preparePrimaryKeyLock(storageProvider, params.secretLockKeyPath, params.syncTimeout)
	if err != nil {
		return nil, err
	}

	localKMS, err := prepareLocalKMS(storageProvider, primaryKeyLock)
	if err != nil {
		return nil, err
	}

	cryptoService, err := tinkcrypto.New()
	if err != nil {
		return nil, err
	}

	jsonLDLoader, err := createJSONLDDocumentLoader(storageProvider)
	if err != nil {
		return nil, err
	}

	authService, err := zcapld.New(localKMS, cryptoService, storageProvider, jsonLDLoader)
	if err != nil {
		return nil, err
	}

	vdrResolver, err := prepareVDR(params)
	if err != nil {
		return nil, err
	}

	kmsService, err := prepareKMSService(storageProvider, primaryKeyLock, localKMS, cryptoService, authService, params)
	if err != nil {
		return nil, err
	}

	return &operation.Config{
		AuthService:  authService,
		KMSService:   kmsService,
		Logger:       log.New("kms/restapi"),
		BaseURL:      params.baseURL,
		JSONLDLoader: jsonLDLoader,
		CryptoBoxCreator: func(keyManager arieskms.KeyManager) (arieskms.CryptoBox, error) {
			return localkms.NewCryptoBox(keyManager)
		},
		VDRResolver: vdrResolver,
	}, nil
}

type secretLockProvider struct {
	storageProvider storage.Provider
	secretLock      secretlock.Service
}

func (p *secretLockProvider) StorageProvider() storage.Provider {
	return p.storageProvider
}

func (p *secretLockProvider) SecretLock() secretlock.Service {
	return p.secretLock
}

func preparePrimaryKeyLock(store storage.Provider, keyPath string, timeout uint64) (secretlock.Service, error) {
	if keyPath == "" {
		return &noop.NoLock{}, nil
	}

	primaryKeyReader, err := local.MasterKeyFromPath(keyPath)
	if err != nil {
		return nil, err
	}

	secLock, err := local.NewService(primaryKeyReader, nil)
	if err != nil {
		return nil, err
	}

	secLockProvider := &secretLockProvider{
		storageProvider: store,
		secretLock:      secLock,
	}

	secretLock, err := lock.New(keystorePrimaryKeyURI, secLockProvider, timeout)
	if err != nil {
		return nil, err
	}

	return secretLock, nil
}

type kmsProvider struct {
	storageProvider storage.Provider
	secretLock      secretlock.Service
}

func (k kmsProvider) StorageProvider() storage.Provider {
	return k.storageProvider
}

func (k kmsProvider) SecretLock() secretlock.Service {
	return k.secretLock
}

func prepareVDR(params *kmsRestParameters) (zcapldcore.VDRResolver, error) {
	rootCAs, err := tlsutils.GetCertPool(params.tlsUseSystemCertPool, params.tlsCACerts)
	if err != nil {
		return nil, err
	}

	orbVDR, err := orb.New(nil, orb.WithDomain(params.didDomain),
		orb.WithTLSConfig(&tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS12}),
	)
	if err != nil {
		return nil, err
	}

	return ariesvdr.New(
		ariesvdr.WithVDR(vdrkey.New()),
		ariesvdr.WithVDR(orbVDR),
	), nil
}

func prepareLocalKMS(storageProvider storage.Provider, primaryKeyLock secretlock.Service) (arieskms.KeyManager, error) {
	provider := &kmsProvider{
		storageProvider: storageProvider,
		secretLock:      primaryKeyLock,
	}

	return localkms.New(keystorePrimaryKeyURI, provider)
}

//nolint:funlen // ignore
func prepareKMSService(storageProvider storage.Provider, primaryKeyLock secretlock.Service,
	localKMS arieskms.KeyManager, cryptoService crypto.Crypto, signer edv.HeaderSigner,
	params *kmsRestParameters) (kms.Service, error) {
	var (
		cacheProvider           storage.Provider
		userKeysStorageProvider storage.Provider
		edvServerURL            string
	)

	if params.cacheExpiration != "" {
		exp, err := time.ParseDuration(params.cacheExpiration)
		if err != nil {
			return nil, err
		}

		cacheProvider = cache.NewProvider(cache.WithExpiration(exp))
	}

	if params.userKeysStorageParams.storageType == storageTypeEDVOption {
		edvServerURL = params.userKeysStorageParams.storageURL
	} else {
		p, err := prepareStorageProvider(params.userKeysStorageParams)
		if err != nil {
			return nil, err
		}

		userKeysStorageProvider = p
	}

	rootCAs, err := tlsutils.GetCertPool(params.tlsUseSystemCertPool, params.tlsCACerts)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS12}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	config := &kms.Config{
		StorageProvider:         storageProvider,
		CacheProvider:           cacheProvider,
		UserKeysStorageProvider: userKeysStorageProvider,
		LocalKMS:                localKMS,
		CryptoService:           cryptoService,
		HeaderSigner:            signer,
		PrimaryKeyLock:          primaryKeyLock,
		CreateSecretLockFunc:    lock.New,
		EDVServerURL:            edvServerURL,
		HubAuthURL:              params.hubAuthURL,
		HubAuthAPIToken:         params.hubAuthAPIToken,
		HTTPClient:              httpClient,
		TLSConfig:               tlsConfig,
		SyncTimeout:             params.syncTimeout,
		Metrics:                 &noopMetrics{},
	}

	if params.hostMetricsURL != "" {
		config.Metrics = prometheus.GetMetrics()
	}

	return kms.NewService(config)
}

func constructCORSHandler(handler http.Handler) http.Handler {
	return cors.New(
		cors.Options{
			AllowedMethods: []string{http.MethodGet, http.MethodPost, http.MethodOptions},
			AllowedHeaders: []string{"*"},
		},
	).Handler(handler)
}

func prepareStorageProvider(params *storageParameters) (storage.Provider, error) {
	switch {
	case strings.EqualFold(params.storageType, storageTypeMemOption):
		return mem.NewProvider(), nil
	case strings.EqualFold(params.storageType, storageTypeCouchDBOption):
		return couchdb.NewProvider(params.storageURL, couchdb.WithDBPrefix(params.storagePrefix))
	case strings.EqualFold(params.storageType, storageTypeMongoDBOption):
		return mongodb.NewProvider(params.storageURL, mongodb.WithDBPrefix(params.storagePrefix))
	default:
		return nil, errors.New("database not set to a valid type")
	}
}

type ldStoreProvider struct {
	ContextStore        ldstore.ContextStore
	RemoteProviderStore ldstore.RemoteProviderStore
}

func (p *ldStoreProvider) JSONLDContextStore() ldstore.ContextStore {
	return p.ContextStore
}

func (p *ldStoreProvider) JSONLDRemoteProviderStore() ldstore.RemoteProviderStore {
	return p.RemoteProviderStore
}

func createJSONLDDocumentLoader(storageProvider storage.Provider) (jsonld.DocumentLoader, error) {
	contextStore, err := ldstore.NewContextStore(storageProvider)
	if err != nil {
		return nil, fmt.Errorf("create JSON-LD context store: %w", err)
	}

	remoteProviderStore, err := ldstore.NewRemoteProviderStore(storageProvider)
	if err != nil {
		return nil, fmt.Errorf("create remote provider store: %w", err)
	}

	ldStore := &ldStoreProvider{
		ContextStore:        contextStore,
		RemoteProviderStore: remoteProviderStore,
	}

	documentLoader, err := ld.NewDocumentLoader(ldStore)
	if err != nil {
		return nil, fmt.Errorf("new document loader: %w", err)
	}

	return documentLoader, nil
}

type noopMetrics struct{}

func (m *noopMetrics) ResolveKeystoreTime(time.Duration) {
}
