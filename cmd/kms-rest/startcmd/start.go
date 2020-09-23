/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/local"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/local/masterlock/hkdf"
	ariesstorage "github.com/hyperledger/aries-framework-go/pkg/storage"
	ariescouchdbstorage "github.com/hyperledger/aries-framework-go/pkg/storage/couchdb"
	ariesmemstorage "github.com/hyperledger/aries-framework-go/pkg/storage/mem"
	"github.com/rs/cors"
	"github.com/spf13/cobra"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/restapi/logspec"
	"github.com/trustbloc/edge-core/pkg/storage"
	couchdbstore "github.com/trustbloc/edge-core/pkg/storage/couchdb"
	"github.com/trustbloc/edge-core/pkg/storage/memstore"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"

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

	logLevelCritical = "critical"
	logLevelError    = "error"
	logLevelWarn     = "warning"
	logLevelInfo     = "info"
	logLevelDebug    = "debug"

	masterKeyURI       = "local-lock://%s"
	masterKeyStoreName = "masterkey"
	masterKeyDBKeyName = masterKeyStoreName

	keySize = sha256.Size
)

var logger = log.New("kms-rest")

type server interface {
	ListenAndServe(host, certFile, keyFile string, router http.Handler) error
}

// HTTPServer represents an actual HTTP server implementation.
type HTTPServer struct{}

// ListenAndServe starts the server using the standard Go HTTP/HTTPS implementation.
func (s *HTTPServer) ListenAndServe(host, certFile, keyFile string, router http.Handler) error {
	if certFile != "" && keyFile != "" {
		return http.ListenAndServeTLS(host, certFile, keyFile, router)
	}

	return http.ListenAndServe(host, router)
}

// GetStartCmd returns the Cobra start command.
func GetStartCmd(srv server) *cobra.Command {
	startCmd := createStartCmd(srv)

	createFlags(startCmd)

	return startCmd
}

func createStartCmd(srv server) *cobra.Command {
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

func startKmsService(parameters *kmsRestParameters, srv server) error {
	if parameters.logLevel != "" {
		setLogLevel(parameters.logLevel)
	}

	router := mux.NewRouter()

	// add health check service API handlers
	healthCheckService := healthcheck.New(log.New("hub-kms-healthcheck"))

	for _, handler := range healthCheckService.GetOperations() {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	// add KMS service API handlers
	opProv, err := createOperationProvider(parameters)
	if err != nil {
		return err
	}

	kmsService := kmsrest.New(opProv)

	for _, handler := range kmsService.GetOperations() {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	// add logspec API handlers
	for _, handler := range logspec.New().GetOperations() {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	logger.Infof("Starting KMS service on host %s", parameters.hostURL)

	return srv.ListenAndServe(
		parameters.hostURL,
		parameters.tlsParams.serveCertPath,
		parameters.tlsParams.serveKeyPath,
		constructCORSHandler(router))
}

type operationProvider struct {
	storageProvider storage.Provider
	kmsCreator      operation.KMSCreator
	crypto          crypto.Crypto
}

func (k operationProvider) StorageProvider() storage.Provider {
	return k.storageProvider
}

func (k operationProvider) KMSCreator() operation.KMSCreator {
	return k.kmsCreator
}

func (k operationProvider) Crypto() crypto.Crypto {
	return k.crypto
}

func setLogLevel(level string) {
	logLevel, err := log.ParseLevel(level)
	if err != nil {
		logger.Warnf("%s is not a valid logging level. It must be one of the following: "+
			"critical, error, warning, info, debug. Defaulting to info.", level)

		logLevel = log.INFO
	}

	log.SetLevel("", logLevel)
}

func createOperationProvider(parameters *kmsRestParameters) (operation.Provider, error) {
	c, err := tinkcrypto.New()
	if err != nil {
		return nil, err
	}

	storageProvider, err := getStorageProvider(parameters.dbParams)
	if err != nil {
		return nil, err
	}

	kmsSecretsStorageProvider, err := getKMSSecretsStorageProvider(parameters.kmsSecretsDBParams)
	if err != nil {
		return nil, err
	}

	return operationProvider{
		storageProvider: storageProvider,
		kmsCreator:      prepareKMSCreator(kmsSecretsStorageProvider),
		crypto:          c,
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

func prepareKMSCreator(kmsStorageProvider ariesstorage.Provider) operation.KMSCreator {
	return func(ctx operation.KMSCreatorContext) (kms.KeyManager, error) {
		keyURI := fmt.Sprintf(masterKeyURI, ctx.KeystoreID)

		secretLock, err := prepareSecretLock(ctx.Passphrase)
		if err != nil {
			return nil, err
		}

		masterKeyReader, err := prepareMasterKeyReader(kmsStorageProvider, secretLock, keyURI)
		if err != nil {
			return nil, err
		}

		secretLockService, err := local.NewService(masterKeyReader, secretLock)
		if err != nil {
			return nil, err
		}

		kmsProv := kmsProvider{
			storageProvider: kmsStorageProvider,
			secretLock:      secretLockService,
		}

		localKMS, err := localkms.New(keyURI, kmsProv)
		if err != nil {
			return nil, err
		}

		return localKMS, nil
	}
}

func prepareSecretLock(passphrase string) (secretlock.Service, error) {
	return hkdf.NewMasterLock(passphrase, sha256.New, nil)
}

func prepareMasterKeyReader(kmsStorageProv ariesstorage.Provider, secLock secretlock.Service,
	keyURI string) (*bytes.Reader, error) {
	masterKeyStore, err := kmsStorageProv.OpenStore(masterKeyStoreName)
	if err != nil {
		return nil, err
	}

	masterKey, err := masterKeyStore.Get(masterKeyDBKeyName)
	if err != nil {
		if errors.Is(err, ariesstorage.ErrDataNotFound) {
			masterKey, err = prepareNewMasterKey(masterKeyStore, secLock, keyURI)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	return bytes.NewReader(masterKey), nil
}

func prepareNewMasterKey(masterKeyStore ariesstorage.Store, secLock secretlock.Service, keyURI string) ([]byte, error) {
	masterKeyContent := randomBytes(keySize)

	masterKeyEnc, err := secLock.Encrypt(keyURI, &secretlock.EncryptRequest{
		Plaintext: string(masterKeyContent),
	})
	if err != nil {
		return nil, err
	}

	masterKey := []byte(masterKeyEnc.Ciphertext)

	err = masterKeyStore.Put(masterKeyDBKeyName, masterKey)
	if err != nil {
		return nil, err
	}

	return masterKey, nil
}

func randomBytes(size uint32) []byte {
	buf := make([]byte, size)

	_, err := rand.Read(buf)
	if err != nil {
		panic(err) // out of randomness, should never happen :-)
	}

	return buf
}

func constructCORSHandler(handler http.Handler) http.Handler {
	return cors.New(
		cors.Options{
			AllowedMethods: []string{http.MethodGet, http.MethodPost},
			AllowedHeaders: []string{"Origin", "Accept", "Content-Type", "X-Requested-With", "Authorization"},
		},
	).Handler(handler)
}
