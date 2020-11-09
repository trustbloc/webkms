/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"errors"
	"net/http"
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

	kmsDatabaseTypeFlagName  = "key-manager-database-type"
	kmsDatabaseTypeEnvKey    = "KMS_KEY_MANAGER_DATABASE_TYPE"
	kmsDatabaseTypeFlagUsage = "The type of database to use for storing KeyManager secrets. " +
		"Supported options: mem, couchdb. " + commonEnvVarUsageText + kmsDatabaseTypeEnvKey

	kmsDatabaseURLFlagName  = "key-manager-database-url"
	kmsDatabaseURLEnvKey    = "KMS_KEY_MANAGER_DATABASE_URL"
	kmsDatabaseURLFlagUsage = "The URL of the database for KMS secrets. Not needed if using in-memory storage. " +
		"For CouchDB, include the username:password@ text if required. " + commonEnvVarUsageText + kmsDatabaseURLEnvKey

	kmsDatabasePrefixFlagName  = "key-manager-database-prefix"
	kmsDatabasePrefixEnvKey    = "KMS_KEY_MANAGER_DATABASE_PREFIX"
	kmsDatabasePrefixFlagUsage = "An optional prefix to be used when creating and retrieving the underlying " +
		"KeyManager secrets database. " + commonEnvVarUsageText + kmsDatabasePrefixEnvKey

	operationalKMSDatabaseTypeFlagName  = "operational-key-manager-database-type"
	operationalKMSDatabaseTypeEnvKey    = "KMS_OPERATIONAL_KEY_MANAGER_DATABASE_TYPE"
	operationalKMSDatabaseTypeFlagUsage = "The type of database to use for storing Operational KeyManager secrets. " +
		"Supported options: mem, couchdb. " + commonEnvVarUsageText + operationalKMSDatabaseTypeEnvKey

	operationalKMSDatabaseURLFlagName  = "operational-key-manager-database-url"
	operationalKMSDatabaseURLEnvKey    = "KMS_OPERATIONAL_KEY_MANAGER_DATABASE_URL"
	operationalKMSDatabaseURLFlagUsage = "The URL of the database for Operational KeyManager secrets. Not needed if " +
		"using in-memory storage. For CouchDB, include the username:password@ text if required. " +
		commonEnvVarUsageText + operationalKMSDatabaseURLEnvKey

	operationalKMSDatabasePrefixFlagName  = "operational-key-manager-database-prefix"
	operationalKMSDatabasePrefixEnvKey    = "KMS_OPERATIONAL_KEY_MANAGER_DATABASE_PREFIX"
	operationalKMSDatabasePrefixFlagUsage = "An optional prefix to be used when creating and retrieving the " +
		"underlying Operational KeyManager secrets database. " + commonEnvVarUsageText + operationalKMSDatabasePrefixEnvKey

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
)

const (
	databaseTypeMemOption     = "mem"
	databaseTypeCouchDBOption = "couchdb"
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

	startCmd.Flags().StringP(databaseTypeFlagName, "", "", databaseTypeFlagUsage)
	startCmd.Flags().StringP(databaseURLFlagName, "", "", databaseURLFlagUsage)
	startCmd.Flags().StringP(databasePrefixFlagName, "", "", databasePrefixFlagUsage)

	startCmd.Flags().StringP(kmsDatabaseTypeFlagName, "", "", kmsDatabaseTypeFlagUsage)
	startCmd.Flags().StringP(kmsDatabaseURLFlagName, "", "", kmsDatabaseURLFlagUsage)
	startCmd.Flags().StringP(kmsDatabasePrefixFlagName, "", "", kmsDatabasePrefixFlagUsage)

	startCmd.Flags().StringP(operationalKMSDatabaseTypeFlagName, "", "", operationalKMSDatabaseTypeFlagUsage)
	startCmd.Flags().StringP(operationalKMSDatabaseURLFlagName, "", "", operationalKMSDatabaseURLFlagUsage)
	startCmd.Flags().StringP(operationalKMSDatabasePrefixFlagName, "", "", operationalKMSDatabasePrefixFlagUsage)

	startCmd.Flags().StringP(tlsServeCertPathFlagName, "", "", tlsServeCertPathFlagUsage)
	startCmd.Flags().StringP(tlsServeKeyPathFlagName, "", "", tlsServeKeyPathFlagUsage)

	startCmd.Flags().StringP(logLevelFlagName, logLevelFlagShorthand, "", logLevelPrefixFlagUsage)
}

type kmsRestParameters struct {
	hostURL                       string
	tlsParams                     *tlsParameters
	dbParams                      *dbParameters
	keyManagerDBParams            *dbParameters
	operationalKeyManagerDBParams *dbParameters
	logLevel                      string
}

type tlsParameters struct {
	serveCertPath string
	serveKeyPath  string
}

type dbParameters struct {
	databaseType   string
	databaseURL    string
	databasePrefix string
}

func getKmsRestParameters(cmd *cobra.Command) (*kmsRestParameters, error) {
	hostURL, err := cmdutils.GetUserSetVarFromString(cmd, hostURLFlagName, hostURLEnvKey, false)
	if err != nil {
		return nil, err
	}

	tlsParams, err := getTLS(cmd)
	if err != nil {
		return nil, err
	}

	dbParams, err := getDBParameters(cmd)
	if err != nil {
		return nil, err
	}

	keyManagerDBParams, err := getKeyManagerDBParameters(cmd)
	if err != nil {
		return nil, err
	}

	operationalKeyManagerDBParams, err := getOperationalKeyManagerDBParameters(cmd)
	if err != nil {
		return nil, err
	}

	logLevel, err := cmdutils.GetUserSetVarFromString(cmd, logLevelFlagName, logLevelEnvKey, true)
	if err != nil {
		return nil, err
	}

	return &kmsRestParameters{
		hostURL:                       hostURL,
		tlsParams:                     tlsParams,
		dbParams:                      dbParams,
		keyManagerDBParams:            keyManagerDBParams,
		operationalKeyManagerDBParams: operationalKeyManagerDBParams,
		logLevel:                      logLevel,
	}, nil
}

func getTLS(cmd *cobra.Command) (*tlsParameters, error) {
	tlsServeCertPath, err := cmdutils.GetUserSetVarFromString(cmd, tlsServeCertPathFlagName,
		tlsServeCertPathEnvKey, true)
	if err != nil {
		return nil, err
	}

	tlsServeKeyPath, err := cmdutils.GetUserSetVarFromString(cmd, tlsServeKeyPathFlagName,
		tlsServeKeyPathFlagEnvKey, true)
	if err != nil {
		return nil, err
	}

	return &tlsParameters{
		serveCertPath: tlsServeCertPath,
		serveKeyPath:  tlsServeKeyPath,
	}, nil
}

func getDBParameters(cmd *cobra.Command) (*dbParameters, error) {
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

	return &dbParameters{
		databaseType:   dbType,
		databaseURL:    dbURL,
		databasePrefix: dbPrefix,
	}, nil
}

func getKeyManagerDBParameters(cmd *cobra.Command) (*dbParameters, error) {
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

	return &dbParameters{
		databaseType:   dbType,
		databaseURL:    dbURL,
		databasePrefix: dbPrefix,
	}, nil
}

func getOperationalKeyManagerDBParameters(cmd *cobra.Command) (*dbParameters, error) {
	dbType, err := cmdutils.GetUserSetVarFromString(cmd, operationalKMSDatabaseTypeFlagName,
		operationalKMSDatabaseTypeEnvKey, false)
	if err != nil {
		return nil, err
	}

	dbURL, err := cmdutils.GetUserSetVarFromString(cmd, operationalKMSDatabaseURLFlagName,
		operationalKMSDatabaseURLEnvKey, true)
	if err != nil {
		return nil, err
	}

	dbPrefix, err := cmdutils.GetUserSetVarFromString(cmd, operationalKMSDatabasePrefixFlagName,
		operationalKMSDatabasePrefixEnvKey, true)
	if err != nil {
		return nil, err
	}

	return &dbParameters{
		databaseType:   dbType,
		databaseURL:    dbURL,
		databasePrefix: dbPrefix,
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
		parameters.tlsParams.serveCertPath,
		parameters.tlsParams.serveKeyPath,
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
	storageProvider, err := getStorageProvider(parameters.dbParams)
	if err != nil {
		return nil, err
	}

	keyManagerStorageProvider, err := getKMSStorageProvider(parameters.keyManagerDBParams)
	if err != nil {
		return nil, err
	}

	operationalKeyManagerStorageProvider, err := getKMSStorageProvider(parameters.operationalKeyManagerDBParams)
	if err != nil {
		return nil, err
	}

	keystoreServiceProv := keystoreServiceProvider{
		storageProvider: storageProvider,
		keyManagerProvider: &kmsProvider{
			storageProvider: keyManagerStorageProvider,
			secretLock:      &noop.NoLock{},
		},
		keyManagerCreator: func(provider arieskms.Provider) (arieskms.KeyManager, error) {
			return kms.NewLocalKMS("local-lock://keystorekms", provider.StorageProvider(), provider.SecretLock())
		},
	}

	keystoreService, err := keystore.NewService(keystoreServiceProv)
	if err != nil {
		return nil, err
	}

	return operationProvider{
		keystoreService:   keystoreService,
		kmsServiceCreator: kms.NewKMSServiceCreator(keystoreService, operationalKeyManagerStorageProvider),
		logger:            log.New("hub-kms/restapi"),
	}, nil
}

func getStorageProvider(params *dbParameters) (storage.Provider, error) {
	switch {
	case strings.EqualFold(params.databaseType, databaseTypeMemOption):
		return memstore.NewProvider(), nil
	case strings.EqualFold(params.databaseType, databaseTypeCouchDBOption):
		return couchdbstore.NewProvider(params.databaseURL, couchdbstore.WithDBPrefix(params.databasePrefix))
	default:
		return nil, errors.New("database not set to a valid type")
	}
}

func getKMSStorageProvider(params *dbParameters) (ariesstorage.Provider, error) {
	switch {
	case strings.EqualFold(params.databaseType, databaseTypeMemOption):
		return ariesmemstorage.NewProvider(), nil
	case strings.EqualFold(params.databaseType, databaseTypeCouchDBOption):
		return ariescouchdbstorage.NewProvider(
			params.databaseURL, ariescouchdbstorage.WithDBPrefix(params.databasePrefix))
	default:
		return nil, errors.New("kms secrets database not set to a valid type")
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
