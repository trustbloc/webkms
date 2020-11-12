/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	ariescouchdbstorage "github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb"
	arieskms "github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	ariesstorage "github.com/hyperledger/aries-framework-go/pkg/storage"
	ariesmemstorage "github.com/hyperledger/aries-framework-go/pkg/storage/mem"
	"github.com/rs/cors"
	"github.com/spf13/cobra"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/restapi/logspec"
	"github.com/trustbloc/edge-core/pkg/storage"
	couchdbstore "github.com/trustbloc/edge-core/pkg/storage/couchdb"
	"github.com/trustbloc/edge-core/pkg/storage/memstore"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"

	"github.com/trustbloc/hub-kms/pkg/keystore"
	"github.com/trustbloc/hub-kms/pkg/kms"
	"github.com/trustbloc/hub-kms/pkg/restapi/healthcheck"
	kmsrest "github.com/trustbloc/hub-kms/pkg/restapi/kms"
	"github.com/trustbloc/hub-kms/pkg/restapi/kms/operation"
)

const (
	commonEnvVarUsageText = "Alternatively, this can be set with the following environment variable: "

	hostURLFlagName  = "host-url"
	hostURLFlagUsage = "URL to run the KMS instance on. Format: HostName:Port."
	hostURLEnvKey    = "KMS_HOST_URL"

	tlsSystemCertPoolFlagName      = "tls-systemcertpool"
	tlsSystemCertPoolFlagShorthand = "s"
	tlsSystemCertPoolFlagUsage     = "Use system certificate pool. Possible values [true] [false]. " +
		"Defaults to false if not set. " + commonEnvVarUsageText + tlsSystemCertPoolEnvKey
	tlsSystemCertPoolEnvKey = "KMS_TLS_SYSTEMCERTPOOL"

	tlsCACertsFlagName      = "tls-cacerts"
	tlsCACertsFlagShorthand = "c"
	tlsCACertsFlagUsage     = "Comma-separated list of CA certs path. " + commonEnvVarUsageText + tlsCACertsEnvKey
	tlsCACertsEnvKey        = "KMS_TLS_CACERTS"

	tlsServeCertPathFlagName  = "tls-serve-cert"
	tlsServeCertPathFlagUsage = "Path to the server certificate to use when serving HTTPS. " +
		commonEnvVarUsageText + tlsServeCertPathEnvKey
	tlsServeCertPathEnvKey = "KMS_TLS_SERVE_CERT"

	tlsServeKeyPathFlagName  = "tls-serve-key"
	tlsServeKeyPathFlagUsage = "Path to the private key to use when serving HTTPS. " +
		commonEnvVarUsageText + tlsServeKeyPathFlagEnvKey
	tlsServeKeyPathFlagEnvKey = "KMS_TLS_SERVE_KEY"

	logLevelFlagName        = "log-level"
	logLevelEnvKey          = "KMS_LOG_LEVEL"
	logLevelFlagShorthand   = "l"
	logLevelPrefixFlagUsage = "Logging level to set. Supported options: critical, error, warning, info, debug. " +
		`Defaults to "info". ` + commonEnvVarUsageText + logLevelEnvKey

	databaseTypeFlagName  = "database-type"
	databaseTypeEnvKey    = "KMS_DATABASE_TYPE"
	databaseTypeFlagUsage = "The type of database to use for storing metadata about keystores and " +
		"associated keys. Supported options: mem, couchdb. " + commonEnvVarUsageText + databaseTypeEnvKey

	databaseURLFlagName  = "database-url"
	databaseURLEnvKey    = "KMS_DATABASE_URL"
	databaseURLFlagUsage = "The URL of the database. Not needed if using in-memory storage. " +
		"For CouchDB, include the username:password@ text if required. " + commonEnvVarUsageText + databaseURLEnvKey

	databasePrefixFlagName  = "database-prefix"
	databasePrefixEnvKey    = "KMS_DATABASE_PREFIX"
	databasePrefixFlagUsage = "An optional prefix to be used when creating and retrieving underlying databases. " +
		commonEnvVarUsageText + databasePrefixEnvKey

	kmsDatabaseTypeFlagName  = "kms-secrets-database-type"
	kmsDatabaseTypeEnvKey    = "KMS_SECRETS_DATABASE_TYPE"
	kmsDatabaseTypeFlagUsage = "The type of database to use for storing KMS secrets for Keystore. " +
		"Supported options: mem, couchdb. " + commonEnvVarUsageText + kmsDatabaseTypeEnvKey

	kmsDatabaseURLFlagName  = "kms-secrets-database-url"
	kmsDatabaseURLEnvKey    = "KMS_SECRETS_DATABASE_URL"
	kmsDatabaseURLFlagUsage = "The URL of the database for KMS secrets. Not needed if using in-memory storage. " +
		"For CouchDB, include the username:password@ text if required. " + commonEnvVarUsageText + kmsDatabaseURLEnvKey

	kmsDatabasePrefixFlagName  = "kms-secrets-database-prefix"
	kmsDatabasePrefixEnvKey    = "KMS_SECRETS_DATABASE_PREFIX"
	kmsDatabasePrefixFlagUsage = "An optional prefix to be used when creating and retrieving the underlying " +
		"KMS secrets database. " + commonEnvVarUsageText + kmsDatabasePrefixEnvKey

	operationalKMSStorageTypeFlagName  = "operational-kms-storage-type"
	operationalKMSStorageTypeEnvKey    = "KMS_OPERATIONAL_KMS_STORAGE_TYPE"
	operationalKMSStorageTypeFlagUsage = "The type of storage to use for Operational (user-specific) KMS. " +
		"Supported options: mem, couchdb, sds. " + commonEnvVarUsageText + operationalKMSStorageTypeEnvKey

	operationalKMSStorageURLFlagName  = "operational-kms-storage-url"
	operationalKMSStorageURLEnvKey    = "KMS_OPERATIONAL_KMS_STORAGE_URL"
	operationalKMSStorageURLFlagUsage = "The URL of storage for Operational KMS. Not needed if using in-memory " +
		"storage. For CouchDB, include the username:password@ text if required. " + commonEnvVarUsageText +
		operationalKMSStorageURLEnvKey

	operationalKMSStoragePrefixFlagName  = "operational-kms-storage-prefix"
	operationalKMSStoragePrefixEnvKey    = "KMS_OPERATIONAL_KMS_STORAGE_PREFIX"
	operationalKMSStoragePrefixFlagUsage = "An optional prefix to be used when creating and retrieving the " +
		"underlying Operational KMS storage. " + commonEnvVarUsageText + operationalKMSStoragePrefixEnvKey
)

const (
	storageTypeMemOption     = "mem"
	storageTypeCouchDBOption = "couchdb"
	storageTypeSDSOption     = "sds"
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
		Long:  "Start kms-rest inside the hub-kms",
		RunE: func(cmd *cobra.Command, args []string) error {
			parameters, err := getKmsRestParameters(cmd)
			if err != nil {
				return err
			}

			return startKmsService(parameters, srv)
		},
	}
}

func createFlags(startCmd *cobra.Command) {
	startCmd.Flags().StringP(hostURLFlagName, "", "", hostURLFlagUsage)

	startCmd.Flags().StringP(tlsSystemCertPoolFlagName, tlsSystemCertPoolFlagShorthand, "", tlsSystemCertPoolFlagUsage)
	startCmd.Flags().StringArrayP(tlsCACertsFlagName, tlsCACertsFlagShorthand, []string{}, tlsCACertsFlagUsage)

	startCmd.Flags().StringP(tlsServeCertPathFlagName, "", "", tlsServeCertPathFlagUsage)
	startCmd.Flags().StringP(tlsServeKeyPathFlagName, "", "", tlsServeKeyPathFlagUsage)

	startCmd.Flags().StringP(logLevelFlagName, logLevelFlagShorthand, "", logLevelPrefixFlagUsage)

	startCmd.Flags().StringP(databaseTypeFlagName, "", "", databaseTypeFlagUsage)
	startCmd.Flags().StringP(databaseURLFlagName, "", "", databaseURLFlagUsage)
	startCmd.Flags().StringP(databasePrefixFlagName, "", "", databasePrefixFlagUsage)

	startCmd.Flags().StringP(kmsDatabaseTypeFlagName, "", "", kmsDatabaseTypeFlagUsage)
	startCmd.Flags().StringP(kmsDatabaseURLFlagName, "", "", kmsDatabaseURLFlagUsage)
	startCmd.Flags().StringP(kmsDatabasePrefixFlagName, "", "", kmsDatabasePrefixFlagUsage)

	startCmd.Flags().StringP(operationalKMSStorageTypeFlagName, "", "", operationalKMSStorageTypeFlagUsage)
	startCmd.Flags().StringP(operationalKMSStorageURLFlagName, "", "", operationalKMSStorageURLFlagUsage)
	startCmd.Flags().StringP(operationalKMSStoragePrefixFlagName, "", "", operationalKMSStoragePrefixFlagUsage)
}

type kmsRestParameters struct {
	hostURL                     string
	tlsUseSystemCertPool        bool
	tlsCACerts                  []string
	tlsServeParams              *tlsServeParameters
	storageParams               *storageParameters
	kmsStorageParams            *storageParameters
	operationalKMSStorageParams *storageParameters
	logLevel                    string
}

type tlsServeParameters struct {
	certPath string
	keyPath  string
}

type storageParameters struct {
	storageType   string
	storageURL    string
	storagePrefix string
}

func getKmsRestParameters(cmd *cobra.Command) (*kmsRestParameters, error) {
	hostURL, err := cmdutils.GetUserSetVarFromString(cmd, hostURLFlagName, hostURLEnvKey, false)
	if err != nil {
		return nil, err
	}

	tlsUseSystemCertPool, tlsCACerts, err := getTLS(cmd)
	if err != nil {
		return nil, err
	}

	tlsServeParams, err := getServeTLS(cmd)
	if err != nil {
		return nil, err
	}

	storageParams, err := getStorageParameters(cmd)
	if err != nil {
		return nil, err
	}

	kmsStorageParams, err := getKMSStorageParameters(cmd)
	if err != nil {
		return nil, err
	}

	operationalKMSStorageParams, err := getOperationalKMSStorageParameters(cmd)
	if err != nil {
		return nil, err
	}

	logLevel, err := cmdutils.GetUserSetVarFromString(cmd, logLevelFlagName, logLevelEnvKey, true)
	if err != nil {
		return nil, err
	}

	return &kmsRestParameters{
		hostURL:                     strings.TrimSpace(hostURL),
		tlsUseSystemCertPool:        tlsUseSystemCertPool,
		tlsCACerts:                  tlsCACerts,
		tlsServeParams:              tlsServeParams,
		storageParams:               storageParams,
		kmsStorageParams:            kmsStorageParams,
		operationalKMSStorageParams: operationalKMSStorageParams,
		logLevel:                    logLevel,
	}, nil
}

func getTLS(cmd *cobra.Command) (bool, []string, error) {
	tlsSystemCertPoolString := cmdutils.GetUserSetOptionalVarFromString(cmd, tlsSystemCertPoolFlagName,
		tlsSystemCertPoolEnvKey)

	tlsUseSystemCertPool := false

	if tlsSystemCertPoolString != "" {
		var err error
		tlsUseSystemCertPool, err = strconv.ParseBool(tlsSystemCertPoolString)

		if err != nil {
			return false, nil, err
		}
	}

	tlsCACerts := cmdutils.GetUserSetOptionalVarFromArrayString(cmd, tlsCACertsFlagName, tlsCACertsEnvKey)

	return tlsUseSystemCertPool, tlsCACerts, nil
}

func getServeTLS(cmd *cobra.Command) (*tlsServeParameters, error) {
	tlsCertPath, err := cmdutils.GetUserSetVarFromString(cmd, tlsServeCertPathFlagName, tlsServeCertPathEnvKey, true)
	if err != nil {
		return nil, err
	}

	tlsKeyPath, err := cmdutils.GetUserSetVarFromString(cmd, tlsServeKeyPathFlagName, tlsServeKeyPathFlagEnvKey, true)
	if err != nil {
		return nil, err
	}

	return &tlsServeParameters{
		certPath: tlsCertPath,
		keyPath:  tlsKeyPath,
	}, nil
}

func getStorageParameters(cmd *cobra.Command) (*storageParameters, error) {
	dbType, err := cmdutils.GetUserSetVarFromString(cmd, databaseTypeFlagName, databaseTypeEnvKey, false)
	if err != nil {
		return nil, err
	}

	dbURL, err := cmdutils.GetUserSetVarFromString(cmd, databaseURLFlagName, databaseURLEnvKey, true)
	if err != nil {
		return nil, err
	}

	dbPrefix, err := cmdutils.GetUserSetVarFromString(cmd, databasePrefixFlagName, databasePrefixEnvKey, true)
	if err != nil {
		return nil, err
	}

	return &storageParameters{
		storageType:   dbType,
		storageURL:    dbURL,
		storagePrefix: dbPrefix,
	}, nil
}

func getKMSStorageParameters(cmd *cobra.Command) (*storageParameters, error) {
	dbType, err := cmdutils.GetUserSetVarFromString(cmd, kmsDatabaseTypeFlagName, kmsDatabaseTypeEnvKey, false)
	if err != nil {
		return nil, err
	}

	dbURL, err := cmdutils.GetUserSetVarFromString(cmd, kmsDatabaseURLFlagName, kmsDatabaseURLEnvKey, true)
	if err != nil {
		return nil, err
	}

	dbPrefix, err := cmdutils.GetUserSetVarFromString(cmd, kmsDatabasePrefixFlagName, kmsDatabasePrefixEnvKey, true)
	if err != nil {
		return nil, err
	}

	return &storageParameters{
		storageType:   dbType,
		storageURL:    dbURL,
		storagePrefix: dbPrefix,
	}, nil
}

func getOperationalKMSStorageParameters(cmd *cobra.Command) (*storageParameters, error) {
	storageType, err := cmdutils.GetUserSetVarFromString(cmd, operationalKMSStorageTypeFlagName,
		operationalKMSStorageTypeEnvKey, false)
	if err != nil {
		return nil, err
	}

	storageURL, err := cmdutils.GetUserSetVarFromString(cmd, operationalKMSStorageURLFlagName,
		operationalKMSStorageURLEnvKey, true)
	if err != nil {
		return nil, err
	}

	storagePrefix, err := cmdutils.GetUserSetVarFromString(cmd, operationalKMSStoragePrefixFlagName,
		operationalKMSStoragePrefixEnvKey, true)
	if err != nil {
		return nil, err
	}

	return &storageParameters{
		storageType:   storageType,
		storageURL:    storageURL,
		storagePrefix: storagePrefix,
	}, nil
}

func startKmsService(parameters *kmsRestParameters, srv Server) error {
	if parameters.logLevel != "" {
		setLogLevel(parameters.logLevel, srv)
	}

	router := mux.NewRouter()

	// add healthcheck API handlers
	healthCheckLogger := log.New("hub-kms/healthcheck")
	healthCheckService := healthcheck.New(healthCheckLogger)

	for _, handler := range healthCheckService.GetOperations() {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	// add KMS API handlers
	opProv, err := createOperationProvider(parameters)
	if err != nil {
		return err
	}

	kmsREST := kmsrest.New(opProv)

	for _, handler := range kmsREST.GetOperations() {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	// add logspec API handlers
	for _, handler := range logspec.New().GetOperations() {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	srv.Logger().Infof("Starting KMS on host %s", parameters.hostURL)

	return srv.ListenAndServe(
		parameters.hostURL,
		parameters.tlsServeParams.certPath,
		parameters.tlsServeParams.keyPath,
		constructCORSHandler(router))
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

type operationProvider struct {
	keystoreService   keystore.Service
	kmsServiceCreator func(req *http.Request) (kms.Service, error)
	logger            log.Logger
}

func (p operationProvider) KeystoreService() keystore.Service {
	return p.keystoreService
}

func (p operationProvider) KMSServiceCreator() func(req *http.Request) (kms.Service, error) {
	return p.kmsServiceCreator
}

func (p operationProvider) Logger() log.Logger {
	return p.logger
}

type keystoreServiceProvider struct {
	storageProvider    storage.Provider
	keyManagerProvider arieskms.Provider
	keyManagerCreator  arieskms.Creator
}

func (p keystoreServiceProvider) StorageProvider() storage.Provider {
	return p.storageProvider
}

func (p keystoreServiceProvider) KeyManagerProvider() arieskms.Provider {
	return p.keyManagerProvider
}

func (p keystoreServiceProvider) KeyManagerCreator() arieskms.Creator {
	return p.keyManagerCreator
}

type kmsProvider struct {
	storageProvider ariesstorage.Provider
	secretLock      secretlock.Service
}

func (k kmsProvider) StorageProvider() ariesstorage.Provider {
	return k.storageProvider
}

func (k kmsProvider) SecretLock() secretlock.Service {
	return k.secretLock
}

func createOperationProvider(parameters *kmsRestParameters) (operation.Provider, error) {
	keystoreService, err := prepareKeystoreService(parameters)
	if err != nil {
		return nil, err
	}

	kmsServiceCreator, err := prepareKMSServiceCreator(keystoreService, parameters)
	if err != nil {
		return nil, err
	}

	return operationProvider{
		keystoreService:   keystoreService,
		kmsServiceCreator: kmsServiceCreator,
		logger:            log.New("hub-kms/restapi"),
	}, nil
}

func prepareKeystoreService(parameters *kmsRestParameters) (keystore.Service, error) {
	const keyURI = "local-lock://keystorekms"

	storageProvider, err := getStorageProvider(parameters.storageParams)
	if err != nil {
		return nil, err
	}

	kmsStorageProvider, err := getKMSStorageProvider(parameters.kmsStorageParams)
	if err != nil {
		return nil, err
	}

	kmsProvider := &kmsProvider{
		storageProvider: kmsStorageProvider,
		secretLock:      &noop.NoLock{},
	}

	kmsCreator := func(provider arieskms.Provider) (arieskms.KeyManager, error) {
		return kms.NewLocalKMS(keyURI, provider.StorageProvider(), provider.SecretLock())
	}

	keystoreServiceProv := keystoreServiceProvider{
		storageProvider:    storageProvider,
		keyManagerProvider: kmsProvider,
		keyManagerCreator:  kmsCreator,
	}

	keystoreService, err := keystore.NewService(keystoreServiceProv)
	if err != nil {
		return nil, err
	}

	return keystoreService, nil
}

func prepareKMSServiceCreator(keystoreService keystore.Service, params *kmsRestParameters) (kms.ServiceCreator, error) {
	operationalKMSStorageProvider, err := getKMSStorageProvider(params.operationalKMSStorageParams)
	if err != nil {
		return nil, err
	}

	return kms.NewServiceCreator(keystoreService, operationalKMSStorageProvider), nil
}

func getStorageProvider(params *storageParameters) (storage.Provider, error) {
	switch {
	case strings.EqualFold(params.storageType, storageTypeMemOption):
		return memstore.NewProvider(), nil
	case strings.EqualFold(params.storageType, storageTypeCouchDBOption):
		return couchdbstore.NewProvider(params.storageURL, couchdbstore.WithDBPrefix(params.storagePrefix))
	default:
		return nil, errors.New("database not set to a valid type")
	}
}

func getKMSStorageProvider(params *storageParameters) (ariesstorage.Provider, error) {
	switch {
	case strings.EqualFold(params.storageType, storageTypeMemOption):
		return ariesmemstorage.NewProvider(), nil
	case strings.EqualFold(params.storageType, storageTypeCouchDBOption):
		return ariescouchdbstorage.NewProvider(
			params.storageURL, ariescouchdbstorage.WithDBPrefix(params.storagePrefix))
	case strings.EqualFold(params.storageType, storageTypeSDSOption):
		return nil, errors.New("KMS storage type not supported yet")
	default:
		return nil, errors.New("KMS storage not set to a valid type")
	}
}

func constructCORSHandler(handler http.Handler) http.Handler {
	return cors.New(
		cors.Options{
			AllowedMethods: []string{http.MethodGet, http.MethodPost},
			AllowedHeaders: []string{"Origin", "Accept", "Content-Type", "X-Requested-With", "Authorization"},
		},
	).Handler(handler)
}
