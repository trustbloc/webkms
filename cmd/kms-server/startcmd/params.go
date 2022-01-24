/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

const (
	commonEnvVarUsageText = "Alternatively, this can be set with the following environment variable: "

	hostEnvKey    = "KMS_HOST"
	hostFlagName  = "host"
	hostFlagUsage = "Host to run the kms-server on. Format: HostName:Port. " +
		commonEnvVarUsageText + hostEnvKey

	hostMetricsEnvKey    = "KMS_METRICS_HOST"
	hostMetricsFlagName  = "metrics-host"
	hostMetricsFlagUsage = "Host to run metrics on. Format: HostName:Port. " +
		commonEnvVarUsageText + hostMetricsEnvKey

	baseURLEnvKey    = "KMS_BASE_URL"
	baseURLFlagName  = "base-url"
	baseURLFlagUsage = "An optional base URL value to prepend to a keystore URL. " +
		commonEnvVarUsageText + baseURLEnvKey

	databaseTypeEnvKey    = "KMS_DATABASE_TYPE"
	databaseTypeFlagName  = "database-type"
	databaseTypeFlagUsage = "The type of database to use for storing keystores metadata. " +
		"Supported options: mem, couchdb, mongodb. " + commonEnvVarUsageText + databaseTypeEnvKey

	databaseURLEnvKey    = "KMS_DATABASE_URL"
	databaseURLFlagName  = "database-url"
	databaseURLFlagUsage = "The URL of the database. Not needed if using in-memory storage. " +
		commonEnvVarUsageText + databaseURLEnvKey

	databasePrefixEnvKey    = "KMS_DATABASE_PREFIX"
	databasePrefixFlagName  = "database-prefix"
	databasePrefixFlagUsage = "An optional prefix to be used when creating and retrieving the underlying database. " +
		commonEnvVarUsageText + databasePrefixEnvKey

	databaseTimeoutEnvKey    = "KMS_DATABASE_TIMEOUT"
	databaseTimeoutFlagName  = "database-timeout"
	databaseTimeoutFlagUsage = "Total time to wait for the database to become available. Supports valid duration " +
		"strings. Defaults to 30s. " + commonEnvVarUsageText + databaseTimeoutEnvKey

	tlsSystemCertPoolEnvKey    = "KMS_TLS_SYSTEMCERTPOOL"
	tlsSystemCertPoolFlagName  = "tls-systemcertpool"
	tlsSystemCertPoolFlagUsage = "Use system certificate pool. Possible values [true] [false]. " +
		"Defaults to false if not set. " + commonEnvVarUsageText + tlsSystemCertPoolEnvKey

	tlsCACertsEnvKey    = "KMS_TLS_CACERTS"
	tlsCACertsFlagName  = "tls-cacerts"
	tlsCACertsFlagUsage = "Comma-separated list of CA certs path. " + commonEnvVarUsageText + tlsCACertsEnvKey

	tlsServeCertPathEnvKey    = "KMS_TLS_SERVE_CERT"
	tlsServeCertPathFlagName  = "tls-serve-cert"
	tlsServeCertPathFlagUsage = "The path to the server certificate to use when serving HTTPS. " +
		commonEnvVarUsageText + tlsServeCertPathEnvKey

	tlsServeKeyPathFlagEnvKey = "KMS_TLS_SERVE_KEY"
	tlsServeKeyPathFlagName   = "tls-serve-key"
	tlsServeKeyPathFlagUsage  = "The path to the private key to use when serving HTTPS. " +
		commonEnvVarUsageText + tlsServeKeyPathFlagEnvKey

	didDomainEnvKey    = "KMS_DID_DOMAIN"
	didDomainFlagName  = "did-domain"
	didDomainFlagUsage = "The URL to the did consortium's domain. " +
		commonEnvVarUsageText + didDomainEnvKey

	authServerURLEnvKey    = "KMS_AUTH_SERVER_URL"
	authServerURLFlagName  = "auth-server-url"
	authServerURLFlagUsage = "The URL of Auth server to use for fetching secret share for shamir secret lock. " +
		"If not specified secret lock based on key is used. " + commonEnvVarUsageText + authServerURLEnvKey

	authServerTokenEnvKey    = "KMS_AUTH_SERVER_TOKEN" //nolint:gosec // not hard-coded credentials
	authServerTokenFlagName  = "auth-server-token"     //nolint:gosec // not hard-coded credentials
	authServerTokenFlagUsage = "A static token used to protect the GET /secrets API in Auth server. " +
		commonEnvVarUsageText + authServerTokenEnvKey

	enableCacheEnvKey    = "KMS_CACHE_ENABLE"
	enableCacheFlagName  = "enable-cache"
	enableCacheFlagUsage = "Enables caching support. Possible values: [true] [false]. Defaults to false. " +
		commonEnvVarUsageText + enableCacheEnvKey

	keyStoreCacheTTLEnvKey    = "KMS_KEY_STORE_CACHE_TTL"
	keyStoreCacheTTLFlagName  = "key-store-cache-ttl"
	keyStoreCacheTTLFlagUsage = "An optional value for key store cache TTL (time to live). Defaults to 10m if " +
		"caching is enabled. If set to 0, key store is never cached. " + commonEnvVarUsageText + keyStoreCacheTTLEnvKey

	kmsCacheTTLEnvKey    = "KMS_KMS_CACHE_TTL"
	kmsCacheTTLFlagName  = "kms-cache-ttl"
	kmsCacheTTLFlagUsage = "An optional value cache TTL (time to live) for keys in server kms. Defaults to 1m if " +
		"caching is enabled. If set to 0, keys are never cached. " + commonEnvVarUsageText + kmsCacheTTLEnvKey

	enableZCAPsEnvKey    = "KMS_ZCAP_ENABLE"
	enableZCAPsFlagName  = "enable-zcap"
	enableZCAPsFlagUsage = "Enables ZCAPs authorization. Possible values: [true] [false]. Defaults to false. " +
		commonEnvVarUsageText + enableZCAPsEnvKey

	enableCORSEnvKey    = "KMS_CORS_ENABLE"
	enableCORSFlagName  = "enable-cors"
	enableCORSFlagUsage = "Enables CORS. Possible values: [true] [false]. Defaults to false. " +
		commonEnvVarUsageText + enableCORSEnvKey

	logLevelEnvKey    = "KMS_LOG_LEVEL"
	logLevelFlagName  = "log-level"
	logLevelFlagUsage = "Logging level. Supported options: critical, error, warning, info, debug. Defaults to info. " +
		commonEnvVarUsageText + logLevelEnvKey

	secretLockTypeFlagName  = "secret-lock-type"
	secretLockTypeEnvKey    = "KMS_SECRET_LOCK_TYPE" //nolint:gosec // not hard-coded credentials
	secretLockTypeFlagUsage = "Type of a secret lock used to protect server KMS. Supported options: local, aws. " +
		commonEnvVarUsageText + secretLockTypeEnvKey

	secretLockKeyPathFlagName  = "secret-lock-key-path"
	secretLockKeyPathEnvKey    = "KMS_SECRET_LOCK_KEY_PATH" //nolint:gosec // not hard-coded credentials
	secretLockKeyPathFlagUsage = "The path to the file with key to be used by local secret lock. If missing noop " +
		"service lock is used. " + commonEnvVarUsageText + secretLockKeyPathEnvKey

	secretLockAWSKeyURIFlagName  = "secret-lock-aws-key-uri"
	secretLockAWSKeyURIEnvKey    = "KMS_SECRET_LOCK_AWS_KEY_URI" //nolint:gosec // not hard-coded credentials
	secretLockAWSKeyURIFlagUsage = "The URI of AWS key to be used by server secret lock" +
		"if the secret lock key type is aws." + commonEnvVarUsageText + secretLockAWSKeyURIEnvKey

	secretLockAWSAccessKeyFlagName  = "secret-lock-aws-access-key"
	secretLockAWSAccessKeyEnvKey    = "KMS_SECRET_LOCK_AWS_ACCESS_KEY" //nolint:gosec // not hard-coded credentials
	secretLockAWSAccessKeyFlagUsage = "The AWS access key ID to be used by server secret lock " +
		"if the secret lock key type is aws." + commonEnvVarUsageText + secretLockAWSAccessKeyEnvKey

	secretLockAWSSecretKeyFlagName  = "secret-lock-aws-secret-key"
	secretLockAWSSecretKeyEnvKey    = "KMS_SECRET_LOCK_AWS_SECRET_KEY" //nolint:gosec // not hard-coded credentials
	secretLockAWSSecretKeyFlagUsage = "The AWS secret access key to be used by server secret lock " +
		"if the secret lock key type is aws." + commonEnvVarUsageText + secretLockAWSSecretKeyEnvKey

	secretLockAWSEndpointFlagName  = "secret-lock-aws-endpoint"
	secretLockAWSEndpointEnvKey    = "KMS_SECRET_LOCK_AWS_ENDPOINT" //nolint:gosec // not hard-coded credentials
	secretLockAWSEndpointFlagUsage = "The endpoint of AWS KMS service. Should be set only in test environment. " +
		commonEnvVarUsageText + secretLockAWSEndpointEnvKey
)

const (
	secretLockTypeAWSOption   = "aws"
	secretLockTypeLocalOption = "local"
)

type serverParameters struct {
	host             string
	metricsHost      string
	baseURL          string
	tlsParams        *tlsParameters
	databaseType     string
	databaseURL      string
	databasePrefix   string
	databaseTimeout  time.Duration
	didDomain        string
	authServerURL    string
	authServerToken  string
	keyStoreCacheTTL time.Duration
	kmsCacheTTL      time.Duration
	enableCache      bool
	enableZCAPs      bool
	enableCORS       bool
	logLevel         string
	secretLockParams *secretLockParameters
}

type tlsParameters struct {
	systemCertPool bool
	caCerts        []string
	serveCertPath  string
	serveKeyPath   string
}

type secretLockParameters struct {
	secretLockType string
	localKeyPath   string
	awsKeyURI      string
	awsEndpoint    string
}

func getParameters(cmd *cobra.Command) (*serverParameters, error) { //nolint:funlen
	host := getUserSetVarOptional(cmd, hostFlagName, hostEnvKey)
	metricsHost := getUserSetVarOptional(cmd, hostMetricsFlagName, hostMetricsEnvKey)
	baseURL := getUserSetVarOptional(cmd, baseURLFlagName, baseURLEnvKey)

	databaseType, err := getUserSetVar(cmd, databaseTypeFlagName, databaseTypeEnvKey, false)
	if err != nil {
		return nil, err
	}

	databaseURL := getUserSetVarOptional(cmd, databaseURLFlagName, databaseURLEnvKey)
	databasePrefix := getUserSetVarOptional(cmd, databasePrefixFlagName, databasePrefixEnvKey)
	databaseTimeoutStr := getUserSetVarOptional(cmd, databaseTimeoutFlagName, databaseTimeoutEnvKey)
	didDomain := getUserSetVarOptional(cmd, didDomainFlagName, didDomainEnvKey)
	authServerURL := getUserSetVarOptional(cmd, authServerURLFlagName, authServerURLEnvKey)
	authServerToken := getUserSetVarOptional(cmd, authServerTokenFlagName, authServerTokenEnvKey)
	keyStoreCacheTTLStr := getUserSetVarOptional(cmd, keyStoreCacheTTLFlagName, keyStoreCacheTTLEnvKey)
	kmsCacheTTLStr := getUserSetVarOptional(cmd, kmsCacheTTLFlagName, kmsCacheTTLEnvKey)
	enableCacheStr := getUserSetVarOptional(cmd, enableCacheFlagName, enableCacheEnvKey)
	enableZCAPsStr := getUserSetVarOptional(cmd, enableZCAPsFlagName, enableZCAPsEnvKey)
	enableCORSStr := getUserSetVarOptional(cmd, enableCORSFlagName, enableCORSEnvKey)
	logLevel := getUserSetVarOptional(cmd, logLevelFlagName, logLevelEnvKey)

	tlsParams, err := getTLS(cmd)
	if err != nil {
		return nil, fmt.Errorf("get TLS: %w", err)
	}

	databaseTimeout, err := time.ParseDuration(databaseTimeoutStr)
	if err != nil {
		return nil, fmt.Errorf("parse database timeout: %w", err)
	}

	var keyStoreCacheTTL time.Duration

	if keyStoreCacheTTLStr != "" {
		keyStoreCacheTTL, err = time.ParseDuration(keyStoreCacheTTLStr)
		if err != nil {
			return nil, fmt.Errorf("parse key store cache ttl: %w", err)
		}
	}

	var kmsCacheTTL time.Duration
	if kmsCacheTTLStr != "" {
		kmsCacheTTL, err = time.ParseDuration(kmsCacheTTLStr)
		if err != nil {
			return nil, fmt.Errorf("parse kms cache ttl: %w", err)
		}
	}

	enableCache, err := strconv.ParseBool(enableCacheStr)
	if err != nil {
		return nil, fmt.Errorf("parse enableCache: %w", err)
	}

	enableZCAPs, err := strconv.ParseBool(enableZCAPsStr)
	if err != nil {
		return nil, fmt.Errorf("parse enableZCAPs: %w", err)
	}

	enableCORS, err := strconv.ParseBool(enableCORSStr)
	if err != nil {
		return nil, fmt.Errorf("parse enableCORS: %w", err)
	}

	secretLockParams, err := getSecretLockParameters(cmd)
	if err != nil {
		return nil, err
	}

	return &serverParameters{
		host:             host,
		metricsHost:      metricsHost,
		baseURL:          baseURL,
		tlsParams:        tlsParams,
		databaseType:     databaseType,
		databaseURL:      databaseURL,
		databasePrefix:   databasePrefix,
		databaseTimeout:  databaseTimeout,
		didDomain:        didDomain,
		authServerURL:    authServerURL,
		authServerToken:  authServerToken,
		keyStoreCacheTTL: keyStoreCacheTTL,
		kmsCacheTTL:      kmsCacheTTL,
		enableCache:      enableCache,
		enableZCAPs:      enableZCAPs,
		enableCORS:       enableCORS,
		logLevel:         logLevel,
		secretLockParams: secretLockParams,
	}, nil
}

func getUserSetVarOptional(cmd *cobra.Command, flagName, envKey string) string {
	val, _ := getUserSetVar(cmd, flagName, envKey, true) //nolint:errcheck // no need to check errors for optional flags

	return val
}

func getUserSetVar(cmd *cobra.Command, flagName, envKey string, isOptional bool) (string, error) {
	defaultOrFlagVal, err := cmd.Flags().GetString(flagName)
	if cmd.Flags().Changed(flagName) {
		return defaultOrFlagVal, err //nolint:wrapcheck
	}

	value, isSet := os.LookupEnv(envKey)
	if isSet {
		return value, nil
	}

	if isOptional || defaultOrFlagVal != "" {
		return defaultOrFlagVal, nil
	}

	return "", fmt.Errorf("neither %s (command line flag) nor %s (environment variable) have been set",
		flagName, envKey)
}

func getTLS(cmd *cobra.Command) (*tlsParameters, error) {
	tlsSystemCertPoolStr := getUserSetVarOptional(cmd, tlsSystemCertPoolFlagName, tlsSystemCertPoolEnvKey)
	tlsCACerts := getUserSetVarOptional(cmd, tlsCACertsFlagName, tlsCACertsEnvKey)
	tlsServeCertPath := getUserSetVarOptional(cmd, tlsServeCertPathFlagName, tlsServeCertPathEnvKey)
	tlsServeKeyPath := getUserSetVarOptional(cmd, tlsServeKeyPathFlagName, tlsServeKeyPathFlagEnvKey)

	tlsSystemCertPool, err := strconv.ParseBool(tlsSystemCertPoolStr)
	if err != nil {
		return nil, fmt.Errorf("parse cert pool: %w", err)
	}

	var caCerts []string
	if tlsCACerts != "" {
		caCerts = strings.Split(tlsCACerts, ",")
	}

	return &tlsParameters{
		systemCertPool: tlsSystemCertPool,
		caCerts:        caCerts,
		serveCertPath:  tlsServeCertPath,
		serveKeyPath:   tlsServeKeyPath,
	}, nil
}

func getSecretLockParameters(cmd *cobra.Command) (*secretLockParameters, error) {
	secretLockType, err := getUserSetVar(cmd, secretLockTypeFlagName, secretLockTypeEnvKey, false)
	if err != nil {
		return nil, err
	}

	localKeyPath, err := getUserSetVar(cmd, secretLockKeyPathFlagName, secretLockKeyPathEnvKey, true)
	if err != nil {
		return nil, err
	}

	isAWS := secretLockType == secretLockTypeAWSOption

	keyURI, err := getUserSetVar(cmd, secretLockAWSKeyURIFlagName, secretLockAWSKeyURIEnvKey, !isAWS)
	if err != nil {
		return nil, err
	}

	awsEndpoint, err := getUserSetVar(cmd, secretLockAWSEndpointFlagName, secretLockAWSEndpointEnvKey, true)
	if err != nil {
		return nil, err
	}

	return &secretLockParameters{
		secretLockType: secretLockType,
		localKeyPath:   localKeyPath,
		awsKeyURI:      keyURI,
		awsEndpoint:    awsEndpoint,
	}, nil
}

func createFlags(startCmd *cobra.Command) {
	startCmd.Flags().String(hostFlagName, "", hostFlagUsage)
	startCmd.Flags().String(hostMetricsFlagName, "", hostMetricsFlagUsage)
	startCmd.Flags().String(baseURLFlagName, "", baseURLFlagUsage)
	startCmd.Flags().String(databaseTypeFlagName, "", databaseTypeFlagUsage)
	startCmd.Flags().String(databaseURLFlagName, "", databaseURLFlagUsage)
	startCmd.Flags().String(databasePrefixFlagName, "", databasePrefixFlagUsage)
	startCmd.Flags().String(databaseTimeoutFlagName, "30s", databaseTimeoutFlagUsage)
	startCmd.Flags().String(tlsSystemCertPoolFlagName, "false", tlsSystemCertPoolFlagUsage)
	startCmd.Flags().String(tlsCACertsFlagName, "", tlsCACertsFlagUsage)
	startCmd.Flags().String(tlsServeCertPathFlagName, "", tlsServeCertPathFlagUsage)
	startCmd.Flags().String(tlsServeKeyPathFlagName, "", tlsServeKeyPathFlagUsage)
	startCmd.Flags().String(didDomainFlagName, "", didDomainFlagUsage)
	startCmd.Flags().String(authServerURLFlagName, "", authServerURLFlagUsage)
	startCmd.Flags().String(authServerTokenFlagName, "", authServerTokenFlagUsage)
	startCmd.Flags().String(keyStoreCacheTTLFlagName, "10m", keyStoreCacheTTLFlagUsage)
	startCmd.Flags().String(kmsCacheTTLFlagName, "1m", kmsCacheTTLFlagUsage)
	startCmd.Flags().String(enableCacheFlagName, "false", enableCacheFlagUsage)
	startCmd.Flags().String(enableZCAPsFlagName, "false", enableZCAPsFlagUsage)
	startCmd.Flags().String(enableCORSFlagName, "false", enableCORSFlagUsage)
	startCmd.Flags().String(logLevelFlagName, "info", logLevelFlagUsage)
	startCmd.Flags().String(secretLockTypeFlagName, "", secretLockTypeFlagUsage)
	startCmd.Flags().String(secretLockKeyPathFlagName, "", secretLockKeyPathFlagUsage)
	startCmd.Flags().String(secretLockAWSKeyURIFlagName, "", secretLockAWSKeyURIFlagUsage)
	startCmd.Flags().String(secretLockAWSAccessKeyFlagName, "", secretLockAWSAccessKeyFlagUsage)
	startCmd.Flags().String(secretLockAWSSecretKeyFlagName, "", secretLockAWSSecretKeyFlagUsage)
	startCmd.Flags().String(secretLockAWSEndpointFlagName, "", secretLockAWSEndpointFlagUsage)
}
