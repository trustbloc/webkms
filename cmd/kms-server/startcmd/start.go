/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	awskms "github.com/aws/aws-sdk-go/service/kms"
	"github.com/cenkalti/backoff/v4"
	"github.com/dgraph-io/ristretto"
	"github.com/google/tink/go/core/registry"
	tinkawskms "github.com/google/tink/go/integration/awskms"
	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb"
	"github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ld"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/local"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/local/masterlock/hkdf"
	ldstore "github.com/hyperledger/aries-framework-go/pkg/store/ld"
	"github.com/hyperledger/aries-framework-go/pkg/vdr"
	vdrkey "github.com/hyperledger/aries-framework-go/pkg/vdr/key"
	logspi "github.com/hyperledger/aries-framework-go/spi/log"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/lafriks/go-shamir"
	jsonld "github.com/piprate/json-gold/ld"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/cors"
	"github.com/spf13/cobra"
	"github.com/square/go-jose/v3"
	"github.com/trustbloc/auth/component/gnap/rs"
	"github.com/trustbloc/auth/spi/gnap/proof/httpsig"
	tlsutil "github.com/trustbloc/edge-core/pkg/utils/tls"
	"github.com/trustbloc/edge-core/pkg/zcapld"

	"github.com/trustbloc/kms/pkg/controller/command"
	"github.com/trustbloc/kms/pkg/controller/mw"
	"github.com/trustbloc/kms/pkg/controller/mw/authmw"
	"github.com/trustbloc/kms/pkg/controller/mw/authmw/gnapmw"
	"github.com/trustbloc/kms/pkg/controller/mw/authmw/oauthmw"
	"github.com/trustbloc/kms/pkg/controller/mw/authmw/zcapmw"
	"github.com/trustbloc/kms/pkg/controller/rest"
	kmscache "github.com/trustbloc/kms/pkg/kms/cache"
	"github.com/trustbloc/kms/pkg/metrics"
	awssecretlock "github.com/trustbloc/kms/pkg/secretlock/aws"
	shamirprovider "github.com/trustbloc/kms/pkg/shamir"
	shamircache "github.com/trustbloc/kms/pkg/shamir/cache"
	"github.com/trustbloc/kms/pkg/storage/cache"
	storagemetrics "github.com/trustbloc/kms/pkg/storage/metrics"
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

	var (
		storageProvider     storage.Provider
		cacheProvider       *cache.Provider
		kmsCacheProvider    *kmscache.Provider
		shamirCacheProvider *shamircache.Provider
	)

	if params.enableCache {
		c, err := ristretto.NewCache(&ristretto.Config{
			NumCounters: 1e7, // TODO: make these values configurable
			MaxCost:     1 << 30,
			BufferItems: 64,
		})
		if err != nil {
			return fmt.Errorf("create ristretto cache: %w", err)
		}

		cacheProvider = &cache.Provider{Cache: c}
		storageProvider = cacheProvider.Wrap(store)
		kmsCacheProvider = &kmscache.Provider{Cache: c}
		shamirCacheProvider = &shamircache.Provider{Cache: c}

	} else {
		storageProvider = store
	}

	kmsService, err := createKMS(storageProvider, params.secretLockParams)
	if err != nil {
		return fmt.Errorf("create kms: %w", err)
	}

	if kmsCacheProvider != nil && params.kmsCacheTTL >= 0 {
		kmsService, err = kmsCacheProvider.WrapKMS(kmsService, params.kmsCacheTTL)
		if err != nil {
			return fmt.Errorf("wrap kms: %w", err)
		}
	}

	cryptoService, err := tinkcrypto.New()
	if err != nil {
		return fmt.Errorf("create tink crypto: %w", err)
	}

	vdrResolver, err := createVDR(params.didDomain, tlsConfig)
	if err != nil {
		return fmt.Errorf("create vdr resolver: %w", err)
	}

	documentLoader, err := createJSONLDDocumentLoader(storageProvider)
	if err != nil {
		return fmt.Errorf("create document loader: %w", err)
	}

	zcapService, err := zcapsvc.New(kmsService, cryptoService, storageProvider, documentLoader)
	if err != nil {
		return fmt.Errorf("create zcap service: %w", err)
	}

	baseKeyStoreURL := params.baseURL + rest.KeyStorePath

	var shamirProvider shamirprovider.Provider

	if params.authServerURL != "" && params.authServerToken != "" {
		shamirProvider = shamirprovider.CreateProvider(&shamirprovider.ProviderConfig{
			HTTPClient:      httpClient,
			AuthServerURL:   params.authServerURL,
			AuthServerToken: params.authServerToken,
		})
	}

	if shamirCacheProvider != nil && shamirProvider != nil && params.shamirSecretCacheTTL >= 0 {
		shamirProvider = shamirCacheProvider.Wrap(shamirProvider, params.shamirSecretCacheTTL)
	}

	config := &command.Config{
		StorageProvider:         storageProvider,
		KeyStorageProvider:      store,
		KMS:                     kmsService,
		Crypto:                  cryptoService,
		VDRResolver:             vdrResolver,
		DocumentLoader:          documentLoader,
		KeyStoreCreator:         &keyStoreCreator{},
		ShamirSecretLockCreator: &shamirSecretLockCreator{},
		CryptBoxCreator:         &cryptoBoxCreator{},
		ZCAPService:             zcapService,
		EnableZCAPs:             !params.disableAuth,
		HeaderSigner:            zcapService,
		TLSConfig:               tlsConfig,
		BaseKeyStoreURL:         baseKeyStoreURL,
		ShamirProvider:          shamirProvider,
		MainKeyType:             kms.AES256GCMType,
		EDVRecipientKeyType:     kms.NISTP256ECDHKW,
		EDVMACKeyType:           kms.HMACSHA256Tag256,
		KeyStoreCacheTTL:        params.keyStoreCacheTTL,
		MetricsProvider:         metrics.Get(),
	}

	if cacheProvider != nil {
		config.CacheProvider = &cacheProviderWithTTL{Provider: cacheProvider}
	}

	cmd, err := command.New(config)
	if err != nil {
		return fmt.Errorf("create command: %w", err)
	}

	router := mux.NewRouter()

	zcapConfig := &zcapmw.ZCAPConfig{
		AuthService:          zcapService,
		JSONLDLoader:         documentLoader,
		Logger:               logger,
		VDRResolver:          vdrResolver,
		BaseResourceURL:      baseKeyStoreURL,
		ResourceIDQueryParam: rest.KeyStoreVarName,
	}

	var (
		privateJWK, publicJWK *jwk.JWK
		gnapRSClient          *rs.Client
	)

	if !params.disableAuth {
		privateJWK, publicJWK, err = createGNAPSigningJWK(params.gnapSigningKeyPath)
		if err != nil {
			return fmt.Errorf("create gnap signing jwk: %w", err)
		}

		gnapRSClient, err = rs.NewClient(
			&httpsig.Signer{SigningKey: privateJWK},
			httpClient,
			params.authServerURL,
		)
	}

	for _, h := range rest.New(cmd).GetRESTHandlers() {
		var handler http.Handler = h.Handler()

		if !params.disableAuth && !h.Auth().HasFlag(rest.AuthNone) {
			middlewares := make([]authmw.Middleware, 0)

			if h.Auth().HasFlag(rest.AuthOAuth2) {
				middlewares = append(middlewares, &oauthmw.Middleware{})
			}

			if h.Auth().HasFlag(rest.AuthZCAP) {
				middlewares = append(middlewares, &zcapmw.Middleware{Config: zcapConfig, Action: h.Action()})
			}

			if h.Auth().HasFlag(rest.AuthGNAP) {
				middlewares = append(middlewares, &gnapmw.Middleware{Client: gnapRSClient, RSPubKey: publicJWK})
			}

			handler = authmw.Wrap(middlewares...)(handler)
		}

		router.Handle(h.Path(), handler).Methods(h.Method())
	}

	var handler http.Handler = router

	if params.enableCORS {
		handler = cors.New(
			cors.Options{
				AllowedMethods: []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodOptions},
				AllowedHeaders: []string{"*"},
				MaxAge:         60,
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
		createProvider = func(string, string) (storage.Provider, error) { //nolint:unparam
			return mem.NewProvider(), nil
		}
	case strings.EqualFold(typ, storageTypeCouchDBOption):
		createProvider = func(url, prefix string) (storage.Provider, error) {
			couchDBProvider, err := couchdb.NewProvider(url, couchdb.WithDBPrefix(prefix))
			if err != nil {
				return nil, err
			}

			return storagemetrics.Wrap(couchDBProvider, "CouchDB"), nil
		}
	case strings.EqualFold(typ, storageTypeMongoDBOption):
		createProvider = func(url, prefix string) (storage.Provider, error) {
			mongoDBProvider, err := mongodb.NewProvider(url, mongodb.WithDBPrefix(prefix))
			if err != nil {
				return nil, err
			}

			return storagemetrics.Wrap(mongoDBProvider, "MongoDB"), nil
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
			awsEndpoint: parameters.awsEndpoint,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("create aws secret lock failed: %w", err)
	}

	return primaryKeyLock, nil
}

func createLocalSecretLock(keyPath string) (secretlock.Service, error) {
	if keyPath == "" {
		return nil, fmt.Errorf("no key defined for local secret lock")
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

func createGNAPSigningJWK(keyFilePath string) (*jwk.JWK, *jwk.JWK, error) {
	b, err := ioutil.ReadFile(keyFilePath)
	if err != nil {
		return nil, nil, fmt.Errorf("read file: %w", err)
	}

	block, _ := pem.Decode(b)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return nil, nil, fmt.Errorf("invalid pem")
	}

	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse private key: %w", err)
	}

	// TODO: make key type configurable
	privateJWK := &jwk.JWK{
		JSONWebKey: jose.JSONWebKey{
			Key:       key,
			Algorithm: "ES256",
		},
		Kty: "EC",
		Crv: "P-256",
	}

	publicJWK := &jwk.JWK{
		JSONWebKey: privateJWK.Public(),
		Kty:        "EC",
		Crv:        "P-256",
	}

	return privateJWK, publicJWK, nil
}

type keyStoreCreator struct{}

func (c *keyStoreCreator) Create(keyURI string, provider kms.Provider) (kms.KeyManager, error) {
	return localkms.New(keyURI, provider)
}

type awsProvider struct {
	awsEndpoint string
}

// NewSession creates a new AWS session with given credentials.
func (a *awsProvider) NewSession(region string) (*session.Session, error) {
	return session.NewSession(&aws.Config{
		Endpoint:                      &a.awsEndpoint,
		Region:                        aws.String(region),
		CredentialsChainVerboseErrors: aws.Bool(true),
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
	combined, err := shamir.Combine(secretShares...)
	if err != nil {
		return nil, fmt.Errorf("shamir combine: %w", err)
	}

	lock, err := hkdf.NewMasterLock(string(combined), sha256.New, nil)
	if err != nil {
		return nil, fmt.Errorf("create hkdf lock: %w", err)
	}

	return lock, nil
}

type cacheProviderWithTTL struct {
	Provider *cache.Provider
}

func (p *cacheProviderWithTTL) Wrap(storageProvider storage.Provider, ttl time.Duration) storage.Provider {
	return p.Provider.Wrap(storageProvider, cache.WithCacheTTL(ttl))
}
