/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"
)

const (
	hostURLFlagName  = "host-url"
	hostURLFlagUsage = "The URL to run the KMS instance on. Format: HostName:Port."
	hostURLEnvKey    = "KMS_HOST_URL"

	hostMetricsURLFlagName  = "host-metrics-url"
	hostMetricsURLFlagUsage = "URL that exposes the metrics endpoint. Format: HostName:Port."
	hostMetricsURLEnvKey    = "KMS_HOST_METRICS_URL"

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

	secretLockKeyPathFlagName  = "secret-lock-key-path"
	secretLockKeyPathEnvKey    = "KMS_SECRET_LOCK_KEY_PATH" //nolint:gosec // not hard-coded credentials
	secretLockKeyPathFlagUsage = "The path to the file with key to be used by local secret lock. If missing noop " +
		"service lock is used. " + commonEnvVarUsageText + secretLockKeyPathEnvKey

	userKeysStorageTypeFlagName  = "user-keys-storage-type"
	userKeysStorageTypeEnvKey    = "KMS_USER_KEYS_STORAGE_TYPE"
	userKeysStorageTypeFlagUsage = "The type of storage to use for user keys. Supported options: mem, couchdb, " +
		"mongodb, edv. " + commonEnvVarUsageText + userKeysStorageTypeEnvKey

	userKeysStorageURLFlagName  = "user-keys-storage-url"
	userKeysStorageURLEnvKey    = "KMS_USER_KEYS_STORAGE_URL"
	userKeysStorageURLFlagUsage = "The URL of storage for user keys. Not needed if using in-memory storage. " +
		"For CouchDB, include the username:password@ text if required. " + commonEnvVarUsageText +
		userKeysStorageURLEnvKey

	userKeysStoragePrefixFlagName  = "user-keys-storage-prefix"
	userKeysStoragePrefixEnvKey    = "KMS_USER_KEYS_STORAGE_PREFIX"
	userKeysStoragePrefixFlagUsage = "An optional prefix to be used when creating and retrieving the underlying " +
		"storage for user keys. " + commonEnvVarUsageText + userKeysStoragePrefixEnvKey

	cacheExpirationFlagName  = "cache-expiration"
	cacheExpirationEnvKey    = "KMS_CACHE_EXPIRATION"
	cacheExpirationFlagUsage = "An optional value for cache expiration. If not set caching is disabled. Supports " +
		"valid duration strings, e.g. 10m, 60s, etc. " + commonEnvVarUsageText + cacheExpirationEnvKey

	hubAuthURLFlagName  = "hub-auth-url"
	hubAuthURLEnvKey    = "KMS_HUB_AUTH_URL"
	hubAuthURLFlagUsage = "The URL of Hub Auth server to use for fetching secret share for secret lock. If not " +
		"specified secret lock based on primary key is used. " + commonEnvVarUsageText + hubAuthURLEnvKey

	hubAuthAPITokenFlagName  = "hub-auth-api-token"     //nolint:gosec // not hard-coded credentials
	hubAuthAPITokenEnvKey    = "KMS_HUB_AUTH_API_TOKEN" //nolint:gosec // not hard-coded credentials
	hubAuthAPITokenFlagUsage = "A static token used to protect the GET /secrets API in Hub Auth. " +
		commonEnvVarUsageText + hubAuthAPITokenEnvKey

	enableZCAPsFlagName  = "enable-zcaps"
	enableZCAPsFlagUsage = "Enables ZCAPs authz on all endpoints (except createKeyStore). Default is false. " +
		commonEnvVarUsageText + enableZCAPsEnvKey
	enableZCAPsEnvKey = "KMS_ZCAP_ENABLE"

	enableCORSFlagName  = "enable-cors"
	enableCORSFlagUsage = "Enables CORS. Possible values [true] [false]. " +
		"Defaults to false if not set. " + commonEnvVarUsageText + corsEnableEnvKey
	corsEnableEnvKey = "KMS_CORS_ENABLE"

	syncTimeoutFlagName  = "sync-timeout"
	syncTimeoutFlagUsage = "Total time in seconds to resolve config values." +
		" Alternatively, this can be set with the following environment variable: " + syncTimeoutEnvKey
	syncTimeoutEnvKey = "KMS_SYNC_TIMEOUT"

	edvRecipientKeyTypeFlagName  = "edv-recipient-key-type"
	edvRecipientKeyTypeEnvKey    = "KMS_EDV_RECIPIENT_KEY_TYPE"
	edvRecipientKeyTypeFlagUsage = "Type of EDV recipient key. " +
		"Possible values NISTP256ECDHKW, NISTP384ECDHKW, NISTP521ECDHKW or X25519ECDHKW. " +
		commonEnvVarUsageText + edvRecipientKeyTypeEnvKey
)

const (
	storageTypeMemOption     = "mem"
	storageTypeCouchDBOption = "couchdb"
	storageTypeMongoDBOption = "mongodb"
	storageTypeEDVOption     = "edv"

	defaultSyncTimeout = "3"
)

type kmsRestParameters struct {
	hostURL               string
	hostMetricsURL        string
	baseURL               string
	tlsUseSystemCertPool  bool
	tlsCACerts            []string
	tlsServeParams        *tlsServeParameters
	storageParams         *storageParameters
	secretLockKeyPath     string
	userKeysStorageParams *storageParameters
	cacheExpiration       string
	hubAuthURL            string
	hubAuthAPIToken       string
	logLevel              string
	enableZCAPs           bool
	enableCORS            bool
	didDomain             string
	syncTimeout           uint64
	edvRecipientKeyType   string
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

	hostMetricsURL, err := cmdutils.GetUserSetVarFromString(cmd, hostMetricsURLFlagName, hostMetricsURLEnvKey, true)
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

	userKeysStorageParams, err := getUserKeysStorageParameters(cmd)
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

	edvRecipientKeyType, err := cmdutils.GetUserSetVarFromString(cmd, edvRecipientKeyTypeFlagName,
		edvRecipientKeyTypeEnvKey, true)
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
		hostURL:               strings.TrimSpace(hostURL),
		hostMetricsURL:        hostMetricsURL,
		baseURL:               baseURL,
		tlsUseSystemCertPool:  tlsUseSystemCertPool,
		tlsCACerts:            tlsCACerts,
		tlsServeParams:        tlsServeParams,
		storageParams:         storageParams,
		secretLockKeyPath:     secretLockKeyPath,
		userKeysStorageParams: userKeysStorageParams,
		cacheExpiration:       cacheExpiration,
		hubAuthURL:            hubAuthURL,
		hubAuthAPIToken:       hubAuthAPIToken,
		logLevel:              logLevel,
		enableZCAPs:           enableZCAPs,
		enableCORS:            enableCORS,
		didDomain:             didDomain,
		syncTimeout:           syncTimeout,
		edvRecipientKeyType:   edvRecipientKeyType,
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

func getUserKeysStorageParameters(cmd *cobra.Command) (*storageParameters, error) {
	storageType, err := cmdutils.GetUserSetVarFromString(cmd, userKeysStorageTypeFlagName,
		userKeysStorageTypeEnvKey, false)
	if err != nil {
		return nil, err
	}

	storageURL, err := cmdutils.GetUserSetVarFromString(cmd, userKeysStorageURLFlagName,
		userKeysStorageURLEnvKey, true)
	if err != nil {
		return nil, err
	}

	storagePrefix, err := cmdutils.GetUserSetVarFromString(cmd, userKeysStoragePrefixFlagName,
		userKeysStoragePrefixEnvKey, true)
	if err != nil {
		return nil, err
	}

	return &storageParameters{
		storageType:   storageType,
		storageURL:    storageURL,
		storagePrefix: storagePrefix,
	}, nil
}

func createFlags(startCmd *cobra.Command) {
	startCmd.Flags().StringP(hostURLFlagName, "", "", hostURLFlagUsage)
	startCmd.Flags().StringP(hostMetricsURLFlagName, "", "", hostMetricsURLFlagUsage)
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

	startCmd.Flags().StringP(userKeysStorageTypeFlagName, "", "", userKeysStorageTypeFlagUsage)
	startCmd.Flags().StringP(userKeysStorageURLFlagName, "", "", userKeysStorageURLFlagUsage)
	startCmd.Flags().StringP(userKeysStoragePrefixFlagName, "", "", userKeysStoragePrefixFlagUsage)

	startCmd.Flags().StringP(cacheExpirationFlagName, "", "", cacheExpirationFlagUsage)

	startCmd.Flags().StringP(hubAuthURLFlagName, "", "", hubAuthURLFlagUsage)
	startCmd.Flags().StringP(hubAuthAPITokenFlagName, "", "", hubAuthAPITokenFlagUsage)

	startCmd.Flags().StringP(enableZCAPsFlagName, "", "", enableZCAPsFlagUsage)
	startCmd.Flags().StringP(enableCORSFlagName, "", "", enableCORSFlagUsage)

	startCmd.Flags().StringP(didDomainFlagName, "", "", didDomainFlagUsage)

	startCmd.Flags().String(syncTimeoutFlagName, "", syncTimeoutFlagUsage)

	startCmd.Flags().String(edvRecipientKeyTypeFlagName, "", edvRecipientKeyTypeFlagUsage)
}
