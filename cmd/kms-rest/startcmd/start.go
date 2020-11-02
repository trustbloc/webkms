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

	hostURLFlagName      = "host-url"
	hostURLFlagShorthand = "u"
	hostURLFlagUsage     = "URL to run the kms-rest instance on. Format: HostName:Port."
	hostURLEnvKey        = "KMS_REST_HOST_URL"

	databaseTypeFlagName      = "database-type"
	databaseTypeEnvKey        = "DATABASE_TYPE"
	databaseTypeFlagShorthand = "t"
	databaseTypeFlagUsage     = "The type of database to use for storing metadata about keystores and" +
		"associated keys. Supported options: mem, couchdb. " + commonEnvVarUsageText + databaseTypeEnvKey

	databaseURLFlagName      = "database-url"
	databaseURLEnvKey        = "DATABASE_URL"
	databaseURLFlagShorthand = "v"
	databaseURLFlagUsage     = "The URL of the database. Not needed if using in-memory storage. " +
		"For CouchDB, include the username:password@ text if required. " + commonEnvVarUsageText + databaseURLEnvKey

	databasePrefixFlagName  = "database-prefix"
	databasePrefixEnvKey    = "DATABASE_PREFIX"
	databasePrefixFlagUsage = "An optional prefix to be used when creating and retrieving underlying databases. " +
		commonEnvVarUsageText + databasePrefixEnvKey

	kmsDatabaseTypeFlagName      = "kms-secrets-database-type"
	kmsDatabaseTypeEnvKey        = "KMS_SECRETS_DATABASE_TYPE"
	kmsDatabaseTypeFlagShorthand = "k"
	kmsDatabaseTypeFlagUsage     = "The type of database to use for storing KMS secrets. " +
		"Supported options: mem, couchdb. " + commonEnvVarUsageText + kmsDatabaseTypeEnvKey

	kmsDatabaseURLFlagName      = "kms-secrets-database-url"
	kmsDatabaseURLEnvKey        = "KMS_SECRETS_DATABASE_URL"
	kmsDatabaseURLFlagShorthand = "s"
	kmsDatabaseURLFlagUsage     = "The URL of the database for KMS secrets. Not needed if using in-memory storage. " +
		"For CouchDB, include the username:password@ text if required. " + commonEnvVarUsageText + kmsDatabaseURLEnvKey

	kmsDatabasePrefixFlagName  = "kms-secrets-database-prefix"
	kmsDatabasePrefixEnvKey    = "KMS_SECRETS_DATABASE_PREFIX"
	kmsDatabasePrefixFlagUsage = "An optional prefix to be used when creating and retrieving the underlying " +
		"KMS secrets database. " + commonEnvVarUsageText + kmsDatabasePrefixEnvKey

	tlsServeCertPathFlagName  = "tls-serve-cert"
	tlsServeCertPathFlagUsage = "Path to the server certificate to use when serving HTTPS. " +
		commonEnvVarUsageText + tlsServeCertPathEnvKey
	tlsServeCertPathEnvKey = "KMS_REST_TLS_SERVE_CERT"

	tlsServeKeyPathFlagName  = "tls-serve-key"
	tlsServeKeyPathFlagUsage = "Path to the private key to use when serving HTTPS. " +
		commonEnvVarUsageText + tlsServeKeyPathFlagEnvKey
	tlsServeKeyPathFlagEnvKey = "KMS_REST_TLS_SERVE_KEY"

	logLevelFlagName        = "log-level"
	logLevelEnvKey          = "KMS_REST_LOG_LEVEL"
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
	startCmd.Flags().StringP(hostURLFlagName, hostURLFlagShorthand, "", hostURLFlagUsage)

	startCmd.Flags().StringP(databaseTypeFlagName, databaseTypeFlagShorthand, "", databaseTypeFlagUsage)
	startCmd.Flags().StringP(databaseURLFlagName, databaseURLFlagShorthand, "", databaseURLFlagUsage)
	startCmd.Flags().StringP(databasePrefixFlagName, "", "", databasePrefixFlagUsage)

	startCmd.Flags().StringP(kmsDatabaseTypeFlagName, kmsDatabaseTypeFlagShorthand, "", kmsDatabaseTypeFlagUsage)
	startCmd.Flags().StringP(kmsDatabaseURLFlagName, kmsDatabaseURLFlagShorthand, "", kmsDatabaseURLFlagUsage)
	startCmd.Flags().StringP(kmsDatabasePrefixFlagName, "", "", kmsDatabasePrefixFlagUsage)

	startCmd.Flags().StringP(tlsServeCertPathFlagName, "", "", tlsServeCertPathFlagUsage)
	startCmd.Flags().StringP(tlsServeKeyPathFlagName, "", "", tlsServeKeyPathFlagUsage)

	startCmd.Flags().StringP(logLevelFlagName, logLevelFlagShorthand, "", logLevelPrefixFlagUsage)
}

type kmsRestParameters struct {
	hostURL            string
	tlsParams          *tlsParameters
	dbParams           *dbParameters
	kmsSecretsDBParams *dbParameters
	logLevel           string
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

	kmsSecretsDBParams, err := getKMSSecretsDBParameters(cmd)
	if err != nil {
		return nil, err
	}

	logLevel, err := cmdutils.GetUserSetVarFromString(cmd, logLevelFlagName, logLevelEnvKey, true)
	if err != nil {
		return nil, err
	}

	return &kmsRestParameters{
		hostURL:            hostURL,
		tlsParams:          tlsParams,
		dbParams:           dbParams,
		kmsSecretsDBParams: kmsSecretsDBParams,
		logLevel:           logLevel,
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

func getKMSSecretsDBParameters(cmd *cobra.Command) (*dbParameters, error) {
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

func startKmsService(parameters *kmsRestParameters, srv Server) error {
	if parameters.logLevel != "" {
		setLogLevel(parameters.logLevel, srv)
	}

	router := mux.NewRouter()

	// add healthcheck API handlers
	healthCheckLogger := log.New("hub-kms-healthcheck")
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

	srv.Logger().Infof("Starting KMS service on host %s", parameters.hostURL)

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

func createOperationProvider(parameters *kmsRestParameters) (operation.Provider, error) {
	storageProvider, err := getStorageProvider(parameters.dbParams)
	if err != nil {
		return nil, err
	}

	keystoreRepo := keystore.NewRepository(storageProvider)

	kmsSecretsStorageProvider, err := getKMSSecretsStorageProvider(parameters.kmsSecretsDBParams)
	if err != nil {
		return nil, err
	}

	return operationProvider{
		keystoreService:   keystore.NewService(keystoreRepo),
		kmsServiceCreator: kms.NewKMSServiceCreator(keystoreRepo, kmsSecretsStorageProvider),
		logger:            log.New("hub-kms-restapi"),
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

func getKMSSecretsStorageProvider(params *dbParameters) (ariesstorage.Provider, error) {
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
