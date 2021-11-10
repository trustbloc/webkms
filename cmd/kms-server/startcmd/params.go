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

	authServerTokenEnvKey    = "KMS_AUTH_SERVER_TOKEN"
	authServerTokenFlagName  = "auth-server-token"
	authServerTokenFlagUsage = "A static token used to protect the GET /secrets API in Auth server. " +
		commonEnvVarUsageText + authServerTokenEnvKey

	cacheExpirationEnvKey    = "KMS_CACHE_EXPIRATION"
	cacheExpirationFlagName  = "cache-expiration"
	cacheExpirationFlagUsage = "An optional value for cache expiration. If not set, caching is disabled. Supports " +
		"valid duration strings (10m, 60s, etc.) " + commonEnvVarUsageText + cacheExpirationEnvKey

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
)

type serverParameters struct {
	host            string
	metricsHost     string
	baseURL         string
	tlsParams       *tlsParameters
	databaseType    string
	databaseURL     string
	databasePrefix  string
	databaseTimeout time.Duration
	didDomain       string
	authServerURL   string
	authServerToken string
	cacheExpiration time.Duration
	enableZCAPs     bool
	enableCORS      bool
	logLevel        string
}

type tlsParameters struct {
	systemCertPool bool
	caCerts        []string
	serveCertPath  string
	serveKeyPath   string
}

func getParameters(cmd *cobra.Command) (*serverParameters, error) {
	host := getUserSetVarOptional(cmd, hostFlagName, hostEnvKey)
	metricsHost := getUserSetVarOptional(cmd, hostMetricsFlagName, hostMetricsEnvKey)
	baseURL := getUserSetVarOptional(cmd, baseURLFlagName, baseURLEnvKey)
	databaseType := getUserSetVarOptional(cmd, databaseTypeFlagName, databaseTypeEnvKey)
	databaseURL := getUserSetVarOptional(cmd, databaseURLFlagName, databaseURLEnvKey)
	databasePrefix := getUserSetVarOptional(cmd, databasePrefixFlagName, databasePrefixEnvKey)
	databaseTimeoutStr := getUserSetVarOptional(cmd, databaseTimeoutFlagName, databaseTimeoutEnvKey)
	didDomain := getUserSetVarOptional(cmd, didDomainFlagName, didDomainEnvKey)
	authServerURL := getUserSetVarOptional(cmd, authServerURLFlagName, authServerURLEnvKey)
	authServerToken := getUserSetVarOptional(cmd, authServerTokenFlagName, authServerTokenEnvKey)
	cacheExpirationStr := getUserSetVarOptional(cmd, cacheExpirationFlagName, cacheExpirationEnvKey)
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

	var cacheExpiration time.Duration

	if cacheExpirationStr != "" {
		cacheExpiration, err = time.ParseDuration(cacheExpirationStr)
		if err != nil {
			return nil, fmt.Errorf("parse cache expiration: %w", err)
		}
	}

	enableZCAPs, err := strconv.ParseBool(enableZCAPsStr)
	if err != nil {
		return nil, fmt.Errorf("parse enableZCAPs: %w", err)
	}

	enableCORS, err := strconv.ParseBool(enableCORSStr)
	if err != nil {
		return nil, fmt.Errorf("parse enableCORS: %w", err)
	}

	return &serverParameters{
		host:            host,
		metricsHost:     metricsHost,
		baseURL:         baseURL,
		tlsParams:       tlsParams,
		databaseType:    databaseType,
		databaseURL:     databaseURL,
		databasePrefix:  databasePrefix,
		databaseTimeout: databaseTimeout,
		didDomain:       didDomain,
		authServerURL:   authServerURL,
		authServerToken: authServerToken,
		cacheExpiration: cacheExpiration,
		enableZCAPs:     enableZCAPs,
		enableCORS:      enableCORS,
		logLevel:        logLevel,
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
	startCmd.Flags().String(cacheExpirationFlagName, "", cacheExpirationFlagUsage)
	startCmd.Flags().String(enableZCAPsFlagName, "false", enableZCAPsFlagUsage)
	startCmd.Flags().String(enableCORSFlagName, "false", enableCORSFlagUsage)
	startCmd.Flags().String(logLevelFlagName, "", logLevelFlagUsage)
}
