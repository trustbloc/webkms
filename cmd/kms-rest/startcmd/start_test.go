/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"testing"

	"github.com/gorilla/mux"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/log/mocklogger"
)

const (
	logLevelCritical = "critical"
	logLevelError    = "error"
	logLevelWarn     = "warning"
	logLevelInfo     = "info"
	logLevelDebug    = "debug"
)

type mockServer struct{}

func (s *mockServer) ListenAndServe(host, certFile, keyFile string, router http.Handler) error {
	return nil
}

func (s *mockServer) Logger() log.Logger {
	return &mocklogger.MockLogger{}
}

func TestListenAndServe(t *testing.T) {
	t.Run("test wrong host", func(t *testing.T) {
		var w httpServer
		err := w.ListenAndServe("wronghost", "", "", nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "address wronghost: missing port in address")
	})

	t.Run("test invalid key file", func(t *testing.T) {
		var w httpServer
		err := w.ListenAndServe("localhost:8080", "test.key", "test.cert", nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "open test.key: no such file or directory")
	})
}

func TestStartCmdContents(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	require.Equal(t, "start", startCmd.Use)
	require.Equal(t, "Start kms-rest", startCmd.Short)
	require.Equal(t, "Start kms-rest inside the hub-kms", startCmd.Long)

	checkFlagPropertiesCorrect(t, startCmd, hostURLFlagName, "", hostURLFlagUsage)
}

func TestStartCmdWithBlankArg(t *testing.T) {
	flags := []string{
		hostURLFlagName, logLevelFlagName,
		tlsServeCertPathFlagName, tlsServeKeyPathFlagName,
		databaseTypeFlagName, databaseURLFlagName, databasePrefixFlagName,
		kmsDatabaseTypeFlagName, kmsDatabaseURLFlagName, kmsDatabasePrefixFlagName,
		operationalKMSStorageTypeFlagName, operationalKMSStorageURLFlagName, operationalKMSStoragePrefixFlagName,
	}

	t.Parallel()

	for _, f := range flags {
		flag := f
		t.Run(fmt.Sprintf("test blank %s arg", flag), func(t *testing.T) {
			startCmd := GetStartCmd(&mockServer{})

			args := buildAllArgsWithOneBlank(flags, flag)
			startCmd.SetArgs(args)

			err := startCmd.Execute()
			require.Error(t, err)
			require.EqualError(t, err, fmt.Sprintf("%s value is empty", flag))
		})
	}
}

func TestStartCmdWithMissingArg(t *testing.T) {
	t.Run("test missing host-url arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{
			"--" + databaseTypeFlagName, storageTypeMemOption,
			"--" + kmsDatabaseTypeFlagName, storageTypeMemOption,
			"--" + operationalKMSStorageTypeFlagName, storageTypeMemOption,
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Equal(t, "Neither host-url (command line flag) nor "+
			"KMS_HOST_URL (environment variable) have been set.",
			err.Error())
	})

	t.Run("test missing database-type arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{
			"--" + hostURLFlagName, "hostname",
			"--" + kmsDatabaseTypeFlagName, storageTypeMemOption,
			"--" + operationalKMSStorageTypeFlagName, storageTypeMemOption,
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
		require.Equal(t, "Neither database-type (command line flag) nor "+
			"KMS_DATABASE_TYPE (environment variable) have been set.",
			err.Error())
	})

	t.Run("test missing kms-secrets-database-type arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{
			"--" + hostURLFlagName, "hostname",
			"--" + databaseTypeFlagName, storageTypeMemOption,
			"--" + operationalKMSStorageTypeFlagName, storageTypeMemOption,
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Equal(t, "Neither kms-secrets-database-type (command line flag) nor "+
			"KMS_SECRETS_DATABASE_TYPE (environment variable) have been set.",
			err.Error())
	})

	t.Run("test missing operational-kms-storage-type arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{
			"--" + hostURLFlagName, "hostname",
			"--" + databaseTypeFlagName, storageTypeMemOption,
			"--" + kmsDatabaseTypeFlagName, storageTypeMemOption,
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Equal(t, "Neither operational-kms-storage-type (command line flag) nor "+
			"KMS_OPERATIONAL_KMS_STORAGE_TYPE (environment variable) have been set.",
			err.Error())
	})
}

func TestStartCmdWithBlankEnvVar(t *testing.T) {
	t.Run("test blank host env var", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		err := os.Setenv(hostURLEnvKey, "")
		require.NoError(t, err)

		err = startCmd.Execute()
		require.Error(t, err)
		require.Equal(t, "KMS_HOST_URL value is empty", err.Error())
	})
}

func TestStartCmdValidArgs(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})
	startCmd.SetArgs(requiredArgs())

	err := startCmd.Execute()
	require.Nil(t, err)
}

func TestStartCmdValidArgsEnvVar(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	setEnvVars(t)
	defer unsetEnvVars(t)

	err := startCmd.Execute()
	require.NoError(t, err)
}

func TestStartCmdLogLevels(t *testing.T) {
	tests := []struct {
		desc string
		in   string
		out  log.Level
	}{
		{`Log level not specified - defaults to "info"`, "", log.INFO},
		{"Log level: critical", logLevelCritical, log.CRITICAL},
		{"Log level: error", logLevelError, log.ERROR},
		{"Log level: warn", logLevelWarn, log.WARNING},
		{"Log level: info", logLevelInfo, log.INFO},
		{"Log level: debug", logLevelDebug, log.DEBUG},
		{"Invalid log level - defaults to info", "invalid log level", log.INFO},
	}

	for _, tt := range tests {
		startCmd := GetStartCmd(&mockServer{})

		args := requiredArgs()

		if tt.in != "" {
			args = append(args, "--"+logLevelFlagName, tt.in)
		}

		startCmd.SetArgs(args)
		err := startCmd.Execute()

		require.Nil(t, err)
		require.Equal(t, tt.out, log.GetLevel(""))
	}
}

func TestStartCmdTLSCertParams(t *testing.T) {
	t.Run("Success with tls-systemcertpool arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := requiredArgs()
		args = append(args, "--"+tlsSystemCertPoolFlagName, "true")

		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Nil(t, err)
	})

	t.Run("Fail with invalid tls-systemcertpool arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := requiredArgs()
		args = append(args, "--"+tlsSystemCertPoolFlagName, "invalid")

		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
	})
}

func TestStartKMSService(t *testing.T) {
	t.Run("Fail to create operation provider", func(t *testing.T) {
		err := startKmsService(&kmsRestParameters{
			storageParams:    &storageParameters{storageType: "invalid"},
			kmsStorageParams: &storageParameters{storageType: storageTypeMemOption},
		}, &mockServer{})

		require.Error(t, err)
	})
}

func TestPrepareOperationConfig(t *testing.T) {
	t.Run("Success with in-memory db option", func(t *testing.T) {
		config, err := prepareOperationConfig(&kmsRestParameters{
			storageParams:               &storageParameters{storageType: storageTypeMemOption},
			kmsStorageParams:            &storageParameters{storageType: storageTypeMemOption},
			operationalKMSStorageParams: &storageParameters{storageType: storageTypeMemOption},
		})

		require.NoError(t, err)
		require.NotNil(t, config)
		require.NotNil(t, config.KeystoreService)
		require.NotNil(t, config.KMSServiceCreator)
		require.NotNil(t, config.Logger)
	})

	// TODO(#53): don't depend on error message defined in external package
	t.Run("Fail with CouchDB option", func(t *testing.T) {
		config, err := prepareOperationConfig(&kmsRestParameters{
			storageParams:               &storageParameters{storageType: storageTypeCouchDBOption, storageURL: "url"},
			kmsStorageParams:            &storageParameters{storageType: storageTypeCouchDBOption, storageURL: "url"},
			operationalKMSStorageParams: &storageParameters{storageType: storageTypeCouchDBOption, storageURL: "url"},
		})

		require.Error(t, err)
		require.Contains(t, err.Error(), "failure while pinging couchDB")
		require.Nil(t, config)
	})

	t.Run("Fail with invalid db option", func(t *testing.T) {
		config, err := prepareOperationConfig(&kmsRestParameters{
			storageParams:               &storageParameters{storageType: "invalid"},
			kmsStorageParams:            &storageParameters{storageType: storageTypeMemOption},
			operationalKMSStorageParams: &storageParameters{storageType: storageTypeMemOption},
		})

		require.Nil(t, config)
		require.Error(t, err)
	})
}

func TestOperationalKMSStorageResolver(t *testing.T) { // TODO(#53): Rewrite this test
	config, err := prepareOperationConfig(&kmsRestParameters{
		storageParams:               &storageParameters{storageType: storageTypeMemOption},
		kmsStorageParams:            &storageParameters{storageType: storageTypeMemOption},
		operationalKMSStorageParams: &storageParameters{storageType: storageTypeSDSOption},
	})

	require.NotNil(t, config)
	require.NoError(t, err)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "",
		bytes.NewBuffer([]byte(`{"passphrase":"p@ssphrase"}`)))
	require.NoError(t, err)

	req = mux.SetURLVars(req, map[string]string{
		"keystoreID": "testKeystoreID",
	})

	srv, err := config.KMSServiceCreator(req)
	require.Nil(t, srv)
	require.Error(t, err)
}

func buildAllArgsWithOneBlank(flags []string, blankArg string) []string {
	var args []string

	for _, f := range flags {
		if f == blankArg {
			args = append(args, "--"+f, "")

			continue
		}

		args = append(args, "--"+f, "value")
	}

	return args
}

func requiredArgs() []string {
	return []string{
		"--" + hostURLFlagName, "localhost:8080",
		"--" + databaseTypeFlagName, storageTypeMemOption,
		"--" + kmsDatabaseTypeFlagName, storageTypeMemOption,
		"--" + operationalKMSStorageTypeFlagName, storageTypeMemOption,
	}
}

func setEnvVars(t *testing.T) {
	err := os.Setenv(hostURLEnvKey, "localhost:8080")
	require.NoError(t, err)

	err = os.Setenv(databaseTypeEnvKey, storageTypeMemOption)
	require.NoError(t, err)

	err = os.Setenv(kmsDatabaseTypeEnvKey, storageTypeMemOption)
	require.NoError(t, err)

	err = os.Setenv(operationalKMSStorageTypeEnvKey, storageTypeMemOption)
	require.NoError(t, err)
}

func unsetEnvVars(t *testing.T) {
	err := os.Unsetenv(hostURLEnvKey)
	require.NoError(t, err)

	err = os.Unsetenv(databaseTypeEnvKey)
	require.NoError(t, err)

	err = os.Unsetenv(kmsDatabaseTypeEnvKey)
	require.NoError(t, err)

	err = os.Unsetenv(operationalKMSStorageTypeEnvKey)
	require.NoError(t, err)
}

func checkFlagPropertiesCorrect(t *testing.T, cmd *cobra.Command, flagName, flagShorthand, flagUsage string) {
	flag := cmd.Flag(flagName)

	require.NotNil(t, flag)
	require.Equal(t, flagName, flag.Name)
	require.Equal(t, flagShorthand, flag.Shorthand)
	require.Equal(t, flagUsage, flag.Usage)
	require.Equal(t, "", flag.Value.String())

	flagAnnotations := flag.Annotations
	require.Nil(t, flagAnnotations)
}
