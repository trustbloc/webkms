/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	awskms "github.com/aws/aws-sdk-go/service/kms"
	"github.com/cenkalti/backoff"
	"github.com/google/tink/go/core/registry"
	tinkawskms "github.com/google/tink/go/integration/awskms"
	"github.com/gorilla/mux"
	"github.com/hashicorp/vault/shamir"
	"github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb"
	"github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ld"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/local"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/local/masterlock/hkdf"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	ldstore "github.com/hyperledger/aries-framework-go/pkg/store/ld"
	"github.com/hyperledger/aries-framework-go/pkg/vdr"
	vdrkey "github.com/hyperledger/aries-framework-go/pkg/vdr/key"
	logspi "github.com/hyperledger/aries-framework-go/spi/log"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	jsonld "github.com/piprate/json-gold/ld"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/cors"
	"github.com/spf13/cobra"
	tlsutil "github.com/trustbloc/edge-core/pkg/utils/tls"
	"github.com/trustbloc/edge-core/pkg/zcapld"

	"github.com/trustbloc/kms/pkg/controller/command"
	"github.com/trustbloc/kms/pkg/controller/mw"
	"github.com/trustbloc/kms/pkg/controller/rest"
	awssecretlock "github.com/trustbloc/kms/pkg/secretlock/aws"
	zcapsvc "github.com/trustbloc/kms/pkg/zcapld"
)

const (
	keystoreLocalPrimaryKeyURI = "local-lock://keystorekms"
)

var logger = log.New("kms-server")

type server interface {
	ListenAndServe(host, certFile, keyFile string, router http.Handler) error
}

// HTTPServer is an actual server implementation.
type HTTPServer struct{}

// ListenAndServe starts the server using the standard HTTP(s) implementation.
func (s *HTTPServer) ListenAndServe(host, certFile, keyFile string, router http.Handler) error {
	if certFile != "" && keyFile != "" {
		return http.ListenAndServeTLS(host, certFile, keyFile, router) //nolint: wrapcheck
	}

	return http.ListenAndServe(host, router) //nolint: wrapcheck
}

// Cmd returns the Cobra start command.
func Cmd(srv server) (*cobra.Command, error) {
	startCmd := createStartCmd(srv)

	createFlags(startCmd)

	return startCmd, nil
}

func createStartCmd(srv server) *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "Starts kms-server",
		Long:  "Starts server for handling key management and crypto operations",
		RunE: func(cmd *cobra.Command, args []string) error {
			parameters, err := getParameters(cmd)
			if err != nil {
				return fmt.Errorf("get parameters: %w", err)
			}

			return startServer(srv, parameters)
		},
	}
}

func startServer(srv server, params *serverParameters) error { //nolint:funlen
	setLogLevel(params.logLevel)

	rootCAs, err := tlsutil.GetCertPool(params.tlsParams.systemCertPool, params.tlsParams.caCerts)
	if err != nil {
		return fmt.Errorf("get cert pool: %w", err)
	}

	tlsConfig := &tls.Config{
		RootCAs:    rootCAs,
		MinVersion: tls.VersionTLS12,
	}

	httpClient := &http.Client{
		Timeout: time.Minute,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	store, err := createStoreProvider(
		params.databaseType,
		params.databaseURL,
		params.databasePrefix,
		params.databaseTimeout,
	)
	if err != nil {
		return fmt.Errorf("create store provider: %w", err)
	}

	kmsService, err := createKMS(store, params.secretLockParams)
	if err != nil {
		return fmt.Errorf("create kms: %w", err)
	}

	cryptoService, err := tinkcrypto.New()
	if err != nil {
		return fmt.Errorf("create tink crypto: %w", err)
	}

	vdrResolver, err := createVDR(params.didDomain, tlsConfig)
	if err != nil {
		return fmt.Errorf("create vdr resolver: %w", err)
	}

	documentLoader, err := createJSONLDDocumentLoader(store)
	if err != nil {
		return fmt.Errorf("create document loader: %w", err)
	}

	zcapService, err := zcapsvc.New(kmsService, cryptoService, store, documentLoader)
	if err != nil {
		return fmt.Errorf("create zcap service: %w", err)
	}

	baseKeyStoreURL := params.baseURL + rest.KeyStorePath

	cmd, err := command.New(&command.Config{
		StorageProvider:         store,
		CacheProvider:           nil,
		KMS:                     kmsService,
		Crypto:                  cryptoService,
		VDRResolver:             vdrResolver,
		DocumentLoader:          documentLoader,
		KeyStoreCreator:         &keyStoreCreator{},
		ShamirSecretLockCreator: &shamirSecretLockCreator{},
		CryptBoxCreator:         &cryptoBoxCreator{},
		ZCAPService:             zcapService,
		HeaderSigner:            zcapService,
		HTTPClient:              httpClient,
		TLSConfig:               tlsConfig,
		BaseKeyStoreURL:         baseKeyStoreURL,
		AuthServerURL:           params.authServerURL,
		AuthServerToken:         params.authServerToken,
		MainKeyType:             kms.AES256GCMType,
		EDVRecipientKeyType:     kms.NISTP256ECDHKW,
		EDVMACKeyType:           kms.HMACSHA256Tag256,
	})
	if err != nil {
		return fmt.Errorf("create command: %w", err)
	}

	router := mux.NewRouter()

	zcapConfig := &mw.ZCAPConfig{
		AuthService:          zcapService,
		JSONLDLoader:         documentLoader,
		Logger:               logger,
		VDRResolver:          vdrResolver,
		BaseResourceURL:      baseKeyStoreURL,
		ResourceIDQueryParam: rest.KeyStoreVarName,
	}

	for _, h := range rest.New(cmd).GetRESTHandlers() {
		var handler http.Handler
		handler = h.Handle()

		if params.enableZCAPs && h.ZCAPProtect() {
			zcapMiddleware := mw.ZCAPLDMiddleware(zcapConfig, h.Action())
			handler = zcapMiddleware(handler)
		}

		router.Handle(h.Path(), handler).Methods(h.Method())
	}

	var handler http.Handler = router

	if params.enableCORS {
		handler = cors.New(
			cors.Options{
				AllowedMethods: []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodOptions},
				AllowedHeaders: []string{"*"},
			},
		).Handler(router)
	}

	if params.metricsHost != "" {
		router.Use(mw.PrometheusMiddleware)

		go startMetrics(srv, params.metricsHost)
	}

	logger.Infof("Starting kms-server on host [%s]", params.host)

	return srv.ListenAndServe(
		params.host,
		params.tlsParams.serveCertPath,
		params.tlsParams.serveKeyPath,
		handler,
	)
}

func setLogLevel(level string) {
	logLevel, err := log.ParseLevel(level)
	if err != nil {
		logger.Warnf("%s is not a valid logging level. It must be one of the following: "+
			"critical, error, warning, info, debug. Defaulting to info.", level)

		logLevel = logspi.INFO
	}

	log.SetLevel("", logLevel)
}

const (
	storageTypeMemOption     = "mem"
	storageTypeCouchDBOption = "couchdb"
	storageTypeMongoDBOption = "mongodb"
)

func createStoreProvider(typ, url, prefix string, timeout time.Duration) (storage.Provider, error) {
	var createProvider func(url, prefix string) (storage.Provider, error)

	switch {
	case strings.EqualFold(typ, storageTypeMemOption):
		createProvider = func(string, string) (storage.Provider, error) {
			return mem.NewProvider(), nil
		}
	case strings.EqualFold(typ, storageTypeCouchDBOption):
		createProvider = func(url, prefix string) (storage.Provider, error) {
			return couchdb.NewProvider(url, couchdb.WithDBPrefix(prefix))
		}
	case strings.EqualFold(typ, storageTypeMongoDBOption):
		createProvider = func(url, prefix string) (storage.Provider, error) {
			return mongodb.NewProvider(url, mongodb.WithDBPrefix(prefix))
		}
	default:
		return nil, fmt.Errorf("not supported database type: %s", typ)
	}

	var store storage.Provider

	var err error

	return store, backoff.RetryNotify(
		func() error {
			store, err = createProvider(url, prefix)

			return err
		},
		backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), uint64(timeout.Seconds())),
		func(retryErr error, t time.Duration) {
			logger.Warnf("Failed to connect to storage, will sleep for %s before trying again: %v", t, retryErr)
		},
	)
}

type kmsProvider struct {
	store      storage.Provider
	secretLock secretlock.Service
}

func (p kmsProvider) StorageProvider() storage.Provider {
	return p.store
}

func (p kmsProvider) SecretLock() secretlock.Service {
	return p.secretLock
}

func createKMS(store storage.Provider, secretLockParams *secretLockParameters) (kms.KeyManager, error) {
	secretLock, primaryKeyURI, err := createSecretLock(secretLockParams)
	if err != nil {
		return nil, fmt.Errorf("create kms secretlock: %w", err)
	}

	return localkms.New(primaryKeyURI, &kmsProvider{
		store:      store,
		secretLock: secretLock,
	})
}

func createVDR(didDomain string, tlsConfig *tls.Config) (zcapld.VDRResolver, error) {
	orbVDR, err := orb.New(nil, orb.WithDomain(didDomain), orb.WithTLSConfig(tlsConfig))
	if err != nil {
		return nil, fmt.Errorf("create orb: %w", err)
	}

	return vdr.New(
		vdr.WithVDR(vdrkey.New()),
		vdr.WithVDR(orbVDR),
	), nil
}

func createSecretLock(parameters *secretLockParameters) (secretlock.Service, string, error) {
	if parameters.secretLockType == secretLockTypeAWSOption {
		secretLock, err := createAwsSecretLock(parameters)

		return secretLock, keystoreLocalPrimaryKeyURI /*parameters.awsKeyURI*/, err
	}

	if parameters.secretLockType == secretLockTypeLocalOption {
		secretLock, err := createLocalSecretLock(parameters.localKeyPath)

		return secretLock, keystoreLocalPrimaryKeyURI, err
	}

	return nil, "", fmt.Errorf("invalid secret lock key type: %s", parameters.secretLockType)
}

func createAwsSecretLock(parameters *secretLockParameters) (secretlock.Service, error) {
	primaryKeyLock, err := awssecretlock.New(
		parameters.awsKeyURI,

		&awsProvider{
			awsEndpoint:     parameters.awsEndpoint,
			accessKeyID:     parameters.awsAccessKeyID,
			secretAccessKey: parameters.awsSecretAccessKey,
		},
	)
	if err != nil {
		return nil, err
	}

	return primaryKeyLock, nil
}

func createLocalSecretLock(keyPath string) (secretlock.Service, error) {
	if keyPath == "" {
		return &noop.NoLock{}, nil
	}

	primaryKeyReader, err := local.MasterKeyFromPath(keyPath)
	if err != nil {
		return nil, err
	}

	secretLock, err := local.NewService(primaryKeyReader, nil)
	if err != nil {
		return nil, err
	}

	return secretLock, nil
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

func createJSONLDDocumentLoader(store storage.Provider) (jsonld.DocumentLoader, error) {
	contextStore, err := ldstore.NewContextStore(store)
	if err != nil {
		return nil, fmt.Errorf("create JSON-LD context store: %w", err)
	}

	remoteProviderStore, err := ldstore.NewRemoteProviderStore(store)
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

type keyStoreCreator struct{}

func (c *keyStoreCreator) Create(keyURI string, provider kms.Provider) (kms.KeyManager, error) {
	return localkms.New(keyURI, provider)
}

type awsProvider struct {
	awsEndpoint     string
	accessKeyID     string
	secretAccessKey string
}

// NewSession creates a new AWS session with given credentials.
func (a *awsProvider) NewSession(region string) (*session.Session, error) {
	return session.NewSession(&aws.Config{
		Endpoint:    &a.awsEndpoint,
		Credentials: credentials.NewStaticCredentials(a.accessKeyID, a.secretAccessKey, ""),
		Region:      aws.String(region),
	})
}

// NewClient returns tink KMSClient that.
func (a *awsProvider) NewClient(uriPrefix string, sess *session.Session) (registry.KMSClient, error) {
	return tinkawskms.NewClientWithKMS(uriPrefix, awskms.New(sess))
}

func startMetrics(srv server, metricsHost string) {
	metricsRouter := mux.NewRouter()

	h := promhttp.HandlerFor(prometheus.DefaultGatherer,
		promhttp.HandlerOpts{
			EnableOpenMetrics: true,
		},
	)

	metricsRouter.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r)
	})

	logger.Infof("Starting KMS metrics on host [%s]", metricsHost)

	if err := srv.ListenAndServe(metricsHost, "", "", metricsRouter); err != nil {
		logger.Fatalf("%v", err)
	}
}

type cryptoBoxCreator struct{}

func (c *cryptoBoxCreator) Create(km kms.KeyManager) (command.CryptoBox, error) {
	return localkms.NewCryptoBox(km)
}

type shamirSecretLockCreator struct{}

func (c *shamirSecretLockCreator) Create(secretShares [][]byte) (secretlock.Service, error) {
	combined, err := shamir.Combine(secretShares)
	if err != nil {
		return nil, fmt.Errorf("shamir combine: %w", err)
	}

	lock, err := hkdf.NewMasterLock(string(combined), sha256.New, nil)
	if err != nil {
		return nil, fmt.Errorf("create hkdf lock: %w", err)
	}

	return lock, nil
}
