/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"fmt"
	"net/http"
	"os"
	"testing"

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

	checkFlagPropertiesCorrect(t, startCmd, hostURLFlagName, hostURLFlagShorthand, hostURLFlagUsage)
}

func TestStartCmdWithBlankArg(t *testing.T) {
	flags := []string{
		hostURLFlagName,
		databaseTypeFlagName, databaseURLFlagName, databasePrefixFlagName,
		kmsDatabaseTypeFlagName, kmsDatabaseURLFlagName, kmsDatabasePrefixFlagName,
		tlsServeCertPathFlagName, tlsServeKeyPathFlagName, logLevelFlagName,
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
			"--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsDatabaseTypeFlagName, databaseTypeMemOption,
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Equal(t, "Neither host-url (command line flag) nor "+
			"KMS_REST_HOST_URL (environment variable) have been set.",
			err.Error())
	})

	t.Run("test missing database-type arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{
			"--" + hostURLFlagName, "hostname",
			"--" + kmsDatabaseTypeFlagName, databaseTypeMemOption,
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
		require.Equal(t, "Neither database-type (command line flag) nor "+
			"DATABASE_TYPE (environment variable) have been set.",
			err.Error())
	})

	t.Run("test missing kms-secrets-database-type arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{
			"--" + hostURLFlagName, "hostname",
			"--" + databaseTypeFlagName, databaseTypeMemOption,
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Equal(t, "Neither kms-secrets-database-type (command line flag) nor "+
			"KMS_SECRETS_DATABASE_TYPE (environment variable) have been set.",
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
		require.Equal(t, "KMS_REST_HOST_URL value is empty", err.Error())
	})
}

func TestStartCmdValidArgs(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	args := []string{
		"--" + hostURLFlagName, "localhost:8080",
		"--" + databaseTypeFlagName, databaseTypeMemOption,
		"--" + kmsDatabaseTypeFlagName, databaseTypeMemOption,
	}
	startCmd.SetArgs(args)

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

		args := []string{
			"--" + hostURLFlagName, "localhost:8080",
			"--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsDatabaseTypeFlagName, databaseTypeMemOption,
		}

		if tt.in != "" {
			args = append(args, "--"+logLevelFlagName, tt.in)
		}

		startCmd.SetArgs(args)
		err := startCmd.Execute()

		require.Nil(t, err)
		require.Equal(t, tt.out, log.GetLevel(""))
	}
}

func TestStartKMSService(t *testing.T) {
	t.Run("Fail to create operation provider", func(t *testing.T) {
		err := startKmsService(&kmsRestParameters{
			dbParams:           &dbParameters{databaseType: "invalid"},
			kmsSecretsDBParams: &dbParameters{databaseType: databaseTypeMemOption},
		}, &mockServer{})

		require.Error(t, err)
	})
}

func TestCreateOperationProvider(t *testing.T) {
	t.Run("Success with in-memory db option", func(t *testing.T) {
		p, err := createOperationProvider(&kmsRestParameters{
			dbParams:           &dbParameters{databaseType: databaseTypeMemOption},
			kmsSecretsDBParams: &dbParameters{databaseType: databaseTypeMemOption},
		})

		require.NoError(t, err)
		require.NotNil(t, p)
		require.NotNil(t, p.KeystoreService())
		require.NotNil(t, p.KMSServiceCreator())
		require.NotNil(t, p.Logger())
	})

	// TODO(#53): don't depend on error message defined in external package
	t.Run("Fail with CouchDB option", func(t *testing.T) {
		p, err := createOperationProvider(&kmsRestParameters{
			dbParams:           &dbParameters{databaseType: databaseTypeCouchDBOption, databaseURL: "url"},
			kmsSecretsDBParams: &dbParameters{databaseType: databaseTypeCouchDBOption, databaseURL: "url"},
		})

		require.Error(t, err)
		require.Contains(t, err.Error(), "failure while pinging couchDB")
		require.Nil(t, p)
	})

	t.Run("Fail with invalid db option", func(t *testing.T) {
		p, err := createOperationProvider(&kmsRestParameters{
			dbParams:           &dbParameters{databaseType: "invalid"},
			kmsSecretsDBParams: &dbParameters{databaseType: databaseTypeMemOption},
		})

		require.Nil(t, p)
		require.Error(t, err)
	})

	t.Run("Fail with invalid kms secrets db option", func(t *testing.T) {
		p, err := createOperationProvider(&kmsRestParameters{
			dbParams:           &dbParameters{databaseType: databaseTypeMemOption},
			kmsSecretsDBParams: &dbParameters{databaseType: "invalid"},
		})

		require.Nil(t, p)
		require.Error(t, err)
	})
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

func setEnvVars(t *testing.T) {
	err := os.Setenv(hostURLEnvKey, "localhost:8080")
	require.NoError(t, err)

	err = os.Setenv(databaseTypeEnvKey, databaseTypeMemOption)
	require.NoError(t, err)

	err = os.Setenv(kmsDatabaseTypeEnvKey, databaseTypeMemOption)
	require.NoError(t, err)
}

func unsetEnvVars(t *testing.T) {
	err := os.Unsetenv(hostURLEnvKey)
	require.NoError(t, err)

	err = os.Unsetenv(databaseTypeEnvKey)
	require.NoError(t, err)

	err = os.Unsetenv(kmsDatabaseTypeEnvKey)
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
