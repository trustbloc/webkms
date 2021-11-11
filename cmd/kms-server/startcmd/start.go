/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/gorilla/mux"
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
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	ldstore "github.com/hyperledger/aries-framework-go/pkg/store/ld"
	"github.com/hyperledger/aries-framework-go/pkg/vdr"
	vdrkey "github.com/hyperledger/aries-framework-go/pkg/vdr/key"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	jsonld "github.com/piprate/json-gold/ld"
	"github.com/rs/cors"
	"github.com/spf13/cobra"
	tlsutil "github.com/trustbloc/edge-core/pkg/utils/tls"
	"github.com/trustbloc/edge-core/pkg/zcapld"

	"github.com/trustbloc/kms/pkg/controller/command"
	"github.com/trustbloc/kms/pkg/controller/rest"
	zcapsvc "github.com/trustbloc/kms/pkg/zcapld"
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

func startServer(srv server, params *serverParameters) error {
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

	kmsService, err := createKMS(store)
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

	cmd, err := command.New(&command.Config{
		StorageProvider:     store,
		CacheProvider:       nil,
		KMS:                 kmsService,
		Crypto:              cryptoService,
		VDRResolver:         vdrResolver,
		DocumentLoader:      documentLoader,
		KeyStoreCreator:     &keyStoreCreator{},
		ZCAPService:         zcapService,
		HeaderSigner:        zcapService,
		HTTPClient:          httpClient,
		TLSConfig:           tlsConfig,
		BaseKeyStoreURL:     params.baseURL + rest.KeyStorePath,
		AuthServerURL:       params.authServerURL,
		AuthServerToken:     params.authServerToken,
		MainKeyType:         kms.ChaCha20Poly1305,
		EDVRecipientKeyType: kms.NISTP256ECDHKW,
		EDVMACKeyType:       kms.HMACSHA256Tag256,
	})
	if err != nil {
		return fmt.Errorf("create command: %w", err)
	}

	router := mux.NewRouter()

	for _, h := range rest.New(cmd).GetRESTHandlers() {
		router.HandleFunc(h.Path(), h.Handle()).Methods(h.Method())
	}

	var handler http.Handler = router

	if params.enableCORS {
		handler = cors.New(
			cors.Options{
				AllowedMethods: []string{http.MethodGet, http.MethodPost, http.MethodOptions},
				AllowedHeaders: []string{"*"},
			},
		).Handler(router)
	}

	logger.Infof("Starting kms-server on host [%s]", params.host)

	return srv.ListenAndServe(
		params.host,
		params.tlsParams.serveCertPath,
		params.tlsParams.serveKeyPath,
		handler,
	)
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

func createKMS(store storage.Provider) (kms.KeyManager, error) {
	// TODO: Implement support for secret lock based on local.NewService() and private key from pem file
	secretLock := &noop.NoLock{}

	return localkms.New("local-lock://noop", &kmsProvider{
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

type keyStoreCreator struct {
}

func (c *keyStoreCreator) Create(keyURI string, provider kms.Provider) (kms.KeyManager, error) {
	return localkms.New(keyURI, provider)
}
