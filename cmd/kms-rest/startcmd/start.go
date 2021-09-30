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
	"strconv"
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
	"github.com/rs/cors"
	"github.com/spf13/cobra"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/restapi/logspec"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"
	tlsutils "github.com/trustbloc/edge-core/pkg/utils/tls"
	zcapldcore "github.com/trustbloc/edge-core/pkg/zcapld"

	"github.com/trustbloc/kms/pkg/auth/zcapld"
	"github.com/trustbloc/kms/pkg/kms"
	"github.com/trustbloc/kms/pkg/restapi/healthcheck"
	"github.com/trustbloc/kms/pkg/restapi/kms/operation"
	lock "github.com/trustbloc/kms/pkg/secretlock"
	"github.com/trustbloc/kms/pkg/storage/cache"
	"github.com/trustbloc/kms/pkg/storage/edv"
)

const (
	hostURLFlagName  = "host-url"
	hostURLFlagUsage = "The URL to run the KMS instance on. Format: HostName:Port."
	hostURLEnvKey    = "KMS_HOST_URL"

	baseURLFlagName  = "base-url"
	baseURLEnvKey    = "KMS_BASE_URL"
	baseURLFlagUsage = "An optional base URL value to prepend to a location returned in the Location header. " +
		commonEnvVarUsageText + baseURLEnvKey

	logLevelFlagName        = "log-level"
	logLevelEnvKey          = "KMS_LOG_LEVEL"
	logLevelFlagShorthand   = "l"
	logLevelPrefixFlagUsage = "Logging level to set. Supported options: critical, error, warning, info, debug. " +
		`Defaults to "info". ` + commonEnvVarUsageText + logLevelEnvKey

	commonEnvVarUsageText = "Alternatively, this can be set with the following environment variable: "

	didDomainFlagName  = "did-domain"
	didDomainFlagUsage = "URL to the did consortium's domain." +
		" Alternatively, this can be set with the following environment variable: " + didDomainEnvKey
	didDomainEnvKey = "KMS_DID_DOMAIN"
)

// TLS options.
const (
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
	tlsServeCertPathFlagUsage = "The path to the server certificate to use when serving HTTPS. " +
		commonEnvVarUsageText + tlsServeCertPathEnvKey
	tlsServeCertPathEnvKey = "KMS_TLS_SERVE_CERT"

	tlsServeKeyPathFlagName  = "tls-serve-key"
	tlsServeKeyPathFlagUsage = "The path to the private key to use when serving HTTPS. " +
		commonEnvVarUsageText + tlsServeKeyPathFlagEnvKey
	tlsServeKeyPathFlagEnvKey = "KMS_TLS_SERVE_KEY"
)

// Storage for Keystore metadata.
const (
	databaseTypeFlagName  = "database-type"
	databaseTypeEnvKey    = "KMS_DATABASE_TYPE"
	databaseTypeFlagUsage = "The type of database to use for storing metadata about keystores and " +
		"associated keys. Supported options: mem, couchdb, mongodb. " + commonEnvVarUsageText + databaseTypeEnvKey

	databaseURLFlagName  = "database-url"
	databaseURLEnvKey    = "KMS_DATABASE_URL"
	databaseURLFlagUsage = "The URL of the database. Not needed if using in-memory storage. " +
		"For CouchDB, include the username:password@ text if required. " + commonEnvVarUsageText + databaseURLEnvKey

	databasePrefixFlagName  = "database-prefix"
	databasePrefixEnvKey    = "KMS_DATABASE_PREFIX"
	databasePrefixFlagUsage = "An optional prefix to be used when creating and retrieving the underlying database. " +
		commonEnvVarUsageText + databasePrefixEnvKey
)

// Path to the file with key to be used by secret lock to protect primary key.
const (
	secretLockKeyPathFlagName  = "secret-lock-key-path"
	secretLockKeyPathEnvKey    = "KMS_SECRET_LOCK_KEY_PATH" //nolint:gosec // not hard-coded credentials
	secretLockKeyPathFlagUsage = "The path to the file with key to be used by local secret lock. If missing noop " +
		"service lock is used. " + commonEnvVarUsageText + secretLockKeyPathEnvKey
)

// Storage for primary keys.
const (
	primaryKeyDatabaseTypeFlagName  = "primary-key-database-type"
	primaryKeyDatabaseTypeEnvKey    = "KMS_PRIMARY_KEY_DATABASE_TYPE"
	primaryKeyDatabaseTypeFlagUsage = "The type of database to use for storing primary keys. " +
		"Supported options: mem, couchdb, mongodb. " + commonEnvVarUsageText + primaryKeyDatabaseTypeEnvKey

	primaryKeyDatabaseURLFlagName  = "primary-key-database-url"
	primaryKeyDatabaseURLEnvKey    = "KMS_PRIMARY_KEY_DATABASE_URL"
	primaryKeyDatabaseURLFlagUsage = "The URL of the database for primary keys. Not needed if using in-memory " +
		"storage. For CouchDB, include the username:password@ text if required. " + commonEnvVarUsageText +
		primaryKeyDatabaseURLEnvKey

	primaryKeyDatabasePrefixFlagName  = "primary-key-database-prefix"
	primaryKeyDatabasePrefixEnvKey    = "KMS_PRIMARY_KEY_DATABASE_PREFIX"
	primaryKeyDatabasePrefixFlagUsage = "An optional prefix to be used when creating and retrieving the underlying " +
		"database for primary keys. " + commonEnvVarUsageText + primaryKeyDatabasePrefixEnvKey
)

// Storage for local KMS (supports Keystore).
const (
	localKMSDatabaseTypeFlagName  = "local-kms-database-type"
	localKMSDatabaseTypeEnvKey    = "KMS_LOCAL_KMS_DATABASE_TYPE"
	localKMSDatabaseTypeFlagUsage = "The type of database to use for storing local KMS secrets (e.g. keys for " +
		"Keystore). Supported options: mem, couchdb, mongodb. " + commonEnvVarUsageText + localKMSDatabaseTypeEnvKey

	localKMSDatabaseURLFlagName  = "local-kms-database-url"
	localKMSDatabaseURLEnvKey    = "KMS_LOCAL_KMS_DATABASE_URL"
	localKMSDatabaseURLFlagUsage = "The URL of the database for local KMS. Not needed if using in-memory storage. " +
		"For CouchDB, include the username:password@ text if required. " +
		commonEnvVarUsageText + localKMSDatabaseURLEnvKey

	localKMSDatabasePrefixFlagName  = "local-kms-database-prefix"
	localKMSDatabasePrefixEnvKey    = "KMS_LOCAL_KMS_DATABASE_PREFIX"
	localKMSDatabasePrefixFlagUsage = "An optional prefix to be used when creating and retrieving the underlying " +
		"local KMS database. " + commonEnvVarUsageText + localKMSDatabasePrefixEnvKey
)

// Storage for Key Manager (KMS that works with user's keys).
const (
	keyManagerStorageTypeFlagName  = "key-manager-storage-type"
	keyManagerStorageTypeEnvKey    = "KMS_KEY_MANAGER_STORAGE_TYPE"
	keyManagerStorageTypeFlagUsage = "The type of storage to use for key manager. Supported options: mem, couchdb, " +
		"mongodb, edv. " + commonEnvVarUsageText + keyManagerStorageTypeEnvKey

	keyManagerStorageURLFlagName  = "key-manager-storage-url"
	keyManagerStorageURLEnvKey    = "KMS_KEY_MANAGER_STORAGE_URL"
	keyManagerStorageURLFlagUsage = "The URL of storage for key manager. Not needed if using in-memory storage. " +
		"For CouchDB, include the username:password@ text if required. " + commonEnvVarUsageText +
		keyManagerStorageURLEnvKey

	keyManagerStoragePrefixFlagName  = "key-manager-storage-prefix"
	keyManagerStoragePrefixEnvKey    = "KMS_KEY_MANAGER_STORAGE_PREFIX"
	keyManagerStoragePrefixFlagUsage = "An optional prefix to be used when creating and retrieving the underlying " +
		"key manager storage. " + commonEnvVarUsageText + keyManagerStoragePrefixEnvKey
)

// Cache expiration (used for EDV and Hub Auth calls).
const (
	cacheExpirationFlagName  = "cache-expiration"
	cacheExpirationEnvKey    = "KMS_CACHE_EXPIRATION"
	cacheExpirationFlagUsage = "An optional value for cache expiration. If not set caching is disabled. Supports " +
		"valid duration strings, e.g. 10m, 60s, etc. " + commonEnvVarUsageText + cacheExpirationEnvKey
)

// Hub Auth integration parameters.
const (
	hubAuthURLFlagName  = "hub-auth-url"
	hubAuthURLEnvKey    = "KMS_HUB_AUTH_URL"
	hubAuthURLFlagUsage = "The URL of Hub Auth server to use for fetching secret share for secret lock. If not " +
		"specified secret lock based on primary key is used. " + commonEnvVarUsageText + hubAuthURLEnvKey

	hubAuthAPITokenFlagName  = "hub-auth-api-token"     //nolint:gosec // not hard-coded credentials
	hubAuthAPITokenEnvKey    = "KMS_HUB_AUTH_API_TOKEN" //nolint:gosec // not hard-coded credentials
	hubAuthAPITokenFlagUsage = "A static token used to protect the GET /secrets API in Hub Auth. " +
		commonEnvVarUsageText + hubAuthAPITokenEnvKey
)

const (
	enableZCAPsFlagName  = "enable-zcaps"
	enableZCAPsFlagUsage = "Enables ZCAPs authz on all endpoints (except createKeyStore). Default is false. " +
		commonEnvVarUsageText + enableZCAPsEnvKey
	enableZCAPsEnvKey = "KMS_ZCAP_ENABLE"

	enableCORSFlagName  = "enable-cors"
	enableCORSFlagUsage = "Enables CORS. Possible values [true] [false]. " +
		"Defaults to false if not set. " + commonEnvVarUsageText + corsEnableEnvKey
	corsEnableEnvKey = "KMS_CORS_ENABLE"
)

const (
	syncTimeoutFlagName  = "sync-timeout"
	syncTimeoutFlagUsage = "Total time in seconds to resolve config values." +
		" Alternatively, this can be set with the following environment variable: " + syncTimeoutEnvKey
	syncTimeoutEnvKey = "KMS_SYNC_TIMEOUT"
)

const (
	storageTypeMemOption     = "mem"
	storageTypeCouchDBOption = "couchdb"
	storageTypeMongoDBOption = "mongodb"
	storageTypeEDVOption     = "edv"
)

const (
	keystorePrimaryKeyURI = "local-lock://keystorekms"
)

const defaultSyncTimeout = "3"

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

func createFlags(startCmd *cobra.Command) {
	startCmd.Flags().StringP(hostURLFlagName, "", "", hostURLFlagUsage)
	startCmd.Flags().StringP(baseURLFlagName, "", "", baseURLFlagUsage)

	startCmd.Flags().StringP(tlsSystemCertPoolFlagName, tlsSystemCertPoolFlagShorthand, "", tlsSystemCertPoolFlagUsage)
	startCmd.Flags().StringArrayP(tlsCACertsFlagName, tlsCACertsFlagShorthand, []string{}, tlsCACertsFlagUsage)

	startCmd.Flags().StringP(tlsServeCertPathFlagName, "", "", tlsServeCertPathFlagUsage)
	startCmd.Flags().StringP(tlsServeKeyPathFlagName, "", "", tlsServeKeyPathFlagUsage)

	startCmd.Flags().StringP(logLevelFlagName, logLevelFlagShorthand, "", logLevelPrefixFlagUsage)

	startCmd.Flags().StringP(databaseTypeFlagName, "", "", databaseTypeFlagUsage)
	startCmd.Flags().StringP(databaseURLFlagName, "", "", databaseURLFlagUsage)
	startCmd.Flags().StringP(databasePrefixFlagName, "", "", databasePrefixFlagUsage)

	startCmd.Flags().StringP(secretLockKeyPathFlagName, "", "", secretLockKeyPathFlagUsage)

	startCmd.Flags().StringP(primaryKeyDatabaseTypeFlagName, "", "", primaryKeyDatabaseTypeFlagUsage)
	startCmd.Flags().StringP(primaryKeyDatabaseURLFlagName, "", "", primaryKeyDatabaseURLFlagUsage)
	startCmd.Flags().StringP(primaryKeyDatabasePrefixFlagName, "", "", primaryKeyDatabasePrefixFlagUsage)

	startCmd.Flags().StringP(localKMSDatabaseTypeFlagName, "", "", localKMSDatabaseTypeFlagUsage)
	startCmd.Flags().StringP(localKMSDatabaseURLFlagName, "", "", localKMSDatabaseURLFlagUsage)
	startCmd.Flags().StringP(localKMSDatabasePrefixFlagName, "", "", localKMSDatabasePrefixFlagUsage)

	startCmd.Flags().StringP(keyManagerStorageTypeFlagName, "", "", keyManagerStorageTypeFlagUsage)
	startCmd.Flags().StringP(keyManagerStorageURLFlagName, "", "", keyManagerStorageURLFlagUsage)
	startCmd.Flags().StringP(keyManagerStoragePrefixFlagName, "", "", keyManagerStoragePrefixFlagUsage)

	startCmd.Flags().StringP(cacheExpirationFlagName, "", "", cacheExpirationFlagUsage)

	startCmd.Flags().StringP(hubAuthURLFlagName, "", "", hubAuthURLFlagUsage)
	startCmd.Flags().StringP(hubAuthAPITokenFlagName, "", "", hubAuthAPITokenFlagUsage)

	startCmd.Flags().StringP(enableZCAPsFlagName, "", "", enableZCAPsFlagUsage)
	startCmd.Flags().StringP(enableCORSFlagName, "", "", enableCORSFlagUsage)

	startCmd.Flags().StringP(didDomainFlagName, "", "", didDomainFlagUsage)

	startCmd.Flags().String(syncTimeoutFlagName, "", syncTimeoutFlagUsage)
}

type kmsRestParameters struct {
	hostURL                 string
	baseURL                 string
	tlsUseSystemCertPool    bool
	tlsCACerts              []string
	tlsServeParams          *tlsServeParameters
	storageParams           *storageParameters
	secretLockKeyPath       string
	primaryKeyStorageParams *storageParameters
	localKMSStorageParams   *storageParameters
	keyManagerStorageParams *storageParameters
	cacheExpiration         string
	hubAuthURL              string
	hubAuthAPIToken         string
	logLevel                string
	enableZCAPs             bool
	enableCORS              bool
	didDomain               string
	syncTimeout             uint64
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

//nolint:gocyclo // no complicated logic here.
func getKmsRestParameters(cmd *cobra.Command) (*kmsRestParameters, error) { //nolint:funlen // better readability
	hostURL, err := cmdutils.GetUserSetVarFromString(cmd, hostURLFlagName, hostURLEnvKey, false)
	if err != nil {
		return nil, err
	}

	baseURL, err := cmdutils.GetUserSetVarFromString(cmd, baseURLFlagName, baseURLEnvKey, true)
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

	logLevel, err := cmdutils.GetUserSetVarFromString(cmd, logLevelFlagName, logLevelEnvKey, true)
	if err != nil {
		return nil, err
	}

	storageParams, err := getStorageParameters(cmd)
	if err != nil {
		return nil, err
	}

	secretLockKeyPath, err := cmdutils.GetUserSetVarFromString(cmd, secretLockKeyPathFlagName,
		secretLockKeyPathEnvKey, true)
	if err != nil {
		return nil, err
	}

	primaryKeyStorageParams, err := getPrimaryKeyStorageParameters(cmd)
	if err != nil {
		return nil, err
	}

	localKMSStorageParams, err := getLocalKMSStorageParameters(cmd)
	if err != nil {
		return nil, err
	}

	keyManagerStorageParams, err := getKeyManagerStorageParameters(cmd)
	if err != nil {
		return nil, err
	}

	cacheExpiration, err := cmdutils.GetUserSetVarFromString(cmd, cacheExpirationFlagName, cacheExpirationEnvKey, true)
	if err != nil {
		return nil, err
	}

	hubAuthURL, err := cmdutils.GetUserSetVarFromString(cmd, hubAuthURLFlagName, hubAuthURLEnvKey, true)
	if err != nil {
		return nil, err
	}

	hubAuthAPIToken, err := cmdutils.GetUserSetVarFromString(cmd, hubAuthAPITokenFlagName, hubAuthAPITokenEnvKey, true)
	if err != nil {
		return nil, err
	}

	didDomain, err := cmdutils.GetUserSetVarFromString(cmd, didDomainFlagName, didDomainEnvKey, true)
	if err != nil {
		return nil, err
	}

	syncTimeoutStr, err := cmdutils.GetUserSetVarFromString(cmd, syncTimeoutFlagName, syncTimeoutEnvKey, true)
	if err != nil {
		return nil, err
	}

	if syncTimeoutStr == "" {
		syncTimeoutStr = defaultSyncTimeout
	}

	syncTimeout, err := strconv.ParseUint(syncTimeoutStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("sync timeout is not a number(positive): %w", err)
	}

	enableZCAPsConfig, err := cmdutils.GetUserSetVarFromString(cmd, enableZCAPsFlagName, enableZCAPsEnvKey, true)
	if err != nil {
		return nil, err
	}

	enableZCAPs := false

	if enableZCAPsConfig != "" {
		enableZCAPs, err = strconv.ParseBool(enableZCAPsConfig)
		if err != nil {
			return nil, err
		}
	}

	enableCORS, err := getEnableCORS(cmd)
	if err != nil {
		return nil, err
	}

	return &kmsRestParameters{
		hostURL:                 strings.TrimSpace(hostURL),
		baseURL:                 baseURL,
		tlsUseSystemCertPool:    tlsUseSystemCertPool,
		tlsCACerts:              tlsCACerts,
		tlsServeParams:          tlsServeParams,
		storageParams:           storageParams,
		secretLockKeyPath:       secretLockKeyPath,
		primaryKeyStorageParams: primaryKeyStorageParams,
		localKMSStorageParams:   localKMSStorageParams,
		keyManagerStorageParams: keyManagerStorageParams,
		cacheExpiration:         cacheExpiration,
		hubAuthURL:              hubAuthURL,
		hubAuthAPIToken:         hubAuthAPIToken,
		logLevel:                logLevel,
		enableZCAPs:             enableZCAPs,
		enableCORS:              enableCORS,
		didDomain:               didDomain,
		syncTimeout:             syncTimeout,
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

func getEnableCORS(cmd *cobra.Command) (bool, error) {
	enableCORSString := cmdutils.GetUserSetOptionalVarFromString(cmd, enableCORSFlagName, corsEnableEnvKey)

	enableCORS := false

	if enableCORSString != "" {
		var err error
		enableCORS, err = strconv.ParseBool(enableCORSString)

		if err != nil {
			return false, err
		}
	}

	return enableCORS, nil
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

func getPrimaryKeyStorageParameters(cmd *cobra.Command) (*storageParameters, error) {
	storageType, err := cmdutils.GetUserSetVarFromString(cmd, primaryKeyDatabaseTypeFlagName,
		primaryKeyDatabaseTypeEnvKey, false)
	if err != nil {
		return nil, err
	}

	storageURL, err := cmdutils.GetUserSetVarFromString(cmd, primaryKeyDatabaseURLFlagName,
		primaryKeyDatabaseURLEnvKey, true)
	if err != nil {
		return nil, err
	}

	storagePrefix, err := cmdutils.GetUserSetVarFromString(cmd, primaryKeyDatabasePrefixFlagName,
		primaryKeyDatabasePrefixEnvKey, true)
	if err != nil {
		return nil, err
	}

	return &storageParameters{
		storageType:   storageType,
		storageURL:    storageURL,
		storagePrefix: storagePrefix,
	}, nil
}

func getLocalKMSStorageParameters(cmd *cobra.Command) (*storageParameters, error) {
	dbType, err := cmdutils.GetUserSetVarFromString(cmd, localKMSDatabaseTypeFlagName,
		localKMSDatabaseTypeEnvKey, false)
	if err != nil {
		return nil, err
	}

	dbURL, err := cmdutils.GetUserSetVarFromString(cmd, localKMSDatabaseURLFlagName,
		localKMSDatabaseURLEnvKey, true)
	if err != nil {
		return nil, err
	}

	dbPrefix, err := cmdutils.GetUserSetVarFromString(cmd, localKMSDatabasePrefixFlagName,
		localKMSDatabasePrefixEnvKey, true)
	if err != nil {
		return nil, err
	}

	return &storageParameters{
		storageType:   dbType,
		storageURL:    dbURL,
		storagePrefix: dbPrefix,
	}, nil
}

func getKeyManagerStorageParameters(cmd *cobra.Command) (*storageParameters, error) {
	storageType, err := cmdutils.GetUserSetVarFromString(cmd, keyManagerStorageTypeFlagName,
		keyManagerStorageTypeEnvKey, false)
	if err != nil {
		return nil, err
	}

	storageURL, err := cmdutils.GetUserSetVarFromString(cmd, keyManagerStorageURLFlagName,
		keyManagerStorageURLEnvKey, true)
	if err != nil {
		return nil, err
	}

	storagePrefix, err := cmdutils.GetUserSetVarFromString(cmd, keyManagerStoragePrefixFlagName,
		keyManagerStoragePrefixEnvKey, true)
	if err != nil {
		return nil, err
	}

	return &storageParameters{
		storageType:   storageType,
		storageURL:    storageURL,
		storagePrefix: storagePrefix,
	}, nil
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

	srv.Logger().Infof("Starting KMS on host %s", params.hostURL)

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

	primaryKeyStorageProvider, err := prepareKMSStorageProvider(params.primaryKeyStorageParams)
	if err != nil {
		return nil, err
	}

	primaryKeyLock, err := preparePrimaryKeyLock(primaryKeyStorageProvider, params.secretLockKeyPath, params.syncTimeout)
	if err != nil {
		return nil, err
	}

	localKMS, err := prepareLocalKMS(primaryKeyLock, params)
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

	kmsService, err := prepareKMSService(storageProvider, primaryKeyStorageProvider, primaryKeyLock,
		localKMS, cryptoService, authService, params)
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

func prepareLocalKMS(primaryKeyLock secretlock.Service, params *kmsRestParameters) (arieskms.KeyManager, error) {
	storageProvider, err := prepareKMSStorageProvider(params.localKMSStorageParams)
	if err != nil {
		return nil, err
	}

	provider := &kmsProvider{
		storageProvider: storageProvider,
		secretLock:      primaryKeyLock,
	}

	return localkms.New(keystorePrimaryKeyURI, provider)
}

func prepareKMSService(storageProvider, primaryKeyStorageProvider storage.Provider, primaryKeyLock secretlock.Service,
	localKMS arieskms.KeyManager, cryptoService crypto.Crypto, signer edv.HeaderSigner,
	params *kmsRestParameters) (kms.Service, error) {
	var (
		cacheProvider             storage.Provider
		keyManagerStorageProvider storage.Provider
		edvServerURL              string
	)

	if params.cacheExpiration != "" {
		exp, err := time.ParseDuration(params.cacheExpiration)
		if err != nil {
			return nil, err
		}

		cacheProvider = cache.NewProvider(cache.WithExpiration(exp))
	}

	if params.keyManagerStorageParams.storageType == storageTypeEDVOption {
		edvServerURL = params.keyManagerStorageParams.storageURL
	} else {
		p, err := prepareKMSStorageProvider(params.keyManagerStorageParams)
		if err != nil {
			return nil, err
		}

		keyManagerStorageProvider = p
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
		StorageProvider:           storageProvider,
		CacheProvider:             cacheProvider,
		KeyManagerStorageProvider: keyManagerStorageProvider,
		LocalKMS:                  localKMS,
		CryptoService:             cryptoService,
		HeaderSigner:              signer,
		PrimaryKeyStorageProvider: primaryKeyStorageProvider,
		PrimaryKeyLock:            primaryKeyLock,
		CreateSecretLockFunc:      lock.New,
		EDVServerURL:              edvServerURL,
		HubAuthURL:                params.hubAuthURL,
		HubAuthAPIToken:           params.hubAuthAPIToken,
		HTTPClient:                httpClient,
		TLSConfig:                 tlsConfig,
		SyncTimeout:               params.syncTimeout,
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

func prepareKMSStorageProvider(params *storageParameters) (storage.Provider, error) {
	switch {
	case strings.EqualFold(params.storageType, storageTypeMemOption):
		return mem.NewProvider(), nil
	case strings.EqualFold(params.storageType, storageTypeCouchDBOption):
		return couchdb.NewProvider(params.storageURL, couchdb.WithDBPrefix(params.storagePrefix))
	case strings.EqualFold(params.storageType, storageTypeMongoDBOption):
		return mongodb.NewProvider(params.storageURL, mongodb.WithDBPrefix(params.storagePrefix))
	default:
		return nil, errors.New("KMS storage not set to a valid type")
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
