/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io/ioutil"
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
	require.Equal(t, "Start kms-rest inside the kms", startCmd.Long)

	checkFlagPropertiesCorrect(t, startCmd, hostURLFlagName, "", hostURLFlagUsage)
}

func TestStartCmdWithBlankArg(t *testing.T) {
	flags := []string{
		hostURLFlagName, baseURLFlagName, logLevelFlagName,
		tlsServeCertPathFlagName, tlsServeKeyPathFlagName, secretLockKeyPathFlagName,
		databaseTypeFlagName, databaseURLFlagName, databasePrefixFlagName,
		primaryKeyDatabaseTypeFlagName, primaryKeyDatabaseURLFlagName, primaryKeyDatabasePrefixFlagName,
		localKMSDatabaseTypeFlagName, localKMSDatabaseURLFlagName, localKMSDatabasePrefixFlagName,
		keyManagerStorageTypeFlagName, keyManagerStorageURLFlagName, keyManagerStoragePrefixFlagName,
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
			"--" + localKMSDatabaseTypeFlagName, storageTypeMemOption,
			"--" + keyManagerStorageTypeFlagName, storageTypeMemOption,
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
			"--" + primaryKeyDatabaseTypeFlagName, storageTypeMemOption,
			"--" + localKMSDatabaseTypeFlagName, storageTypeMemOption,
			"--" + keyManagerStorageTypeFlagName, storageTypeMemOption,
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
		require.Equal(t, "Neither database-type (command line flag) nor "+
			"KMS_DATABASE_TYPE (environment variable) have been set.",
			err.Error())
	})

	t.Run("test missing primary-key-database-type arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{
			"--" + hostURLFlagName, "hostname",
			"--" + databaseTypeFlagName, storageTypeMemOption,
			"--" + localKMSDatabaseTypeFlagName, storageTypeMemOption,
			"--" + keyManagerStorageTypeFlagName, storageTypeMemOption,
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Equal(t, "Neither primary-key-database-type (command line flag) nor "+
			"KMS_PRIMARY_KEY_DATABASE_TYPE (environment variable) have been set.",
			err.Error())
	})

	t.Run("test missing local-kms-database-type arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{
			"--" + hostURLFlagName, "hostname",
			"--" + databaseTypeFlagName, storageTypeMemOption,
			"--" + primaryKeyDatabaseTypeFlagName, storageTypeMemOption,
			"--" + keyManagerStorageTypeFlagName, storageTypeMemOption,
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Equal(t, "Neither local-kms-database-type (command line flag) nor "+
			"KMS_LOCAL_KMS_DATABASE_TYPE (environment variable) have been set.",
			err.Error())
	})

	t.Run("test missing key-manager-storage-type arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{
			"--" + hostURLFlagName, "hostname",
			"--" + databaseTypeFlagName, storageTypeMemOption,
			"--" + primaryKeyDatabaseTypeFlagName, storageTypeMemOption,
			"--" + localKMSDatabaseTypeFlagName, storageTypeMemOption,
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Equal(t, "Neither key-manager-storage-type (command line flag) nor "+
			"KMS_KEY_MANAGER_STORAGE_TYPE (environment variable) have been set.",
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

func TestStartCmdWithTLSCertParams(t *testing.T) {
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

func TestStartCmdWithSecretLockKeyPathParam(t *testing.T) {
	t.Run("Success with valid key file", func(t *testing.T) {
		file, closeFunc := createKeyFile(t, false)
		defer closeFunc()

		startCmd := GetStartCmd(&mockServer{})

		args := requiredArgs()
		args = append(args, "--"+secretLockKeyPathFlagName, file)

		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.NoError(t, err)
	})

	t.Run("Fail with invalid key file content", func(t *testing.T) {
		file, closeFunc := createKeyFile(t, true)
		defer closeFunc()

		startCmd := GetStartCmd(&mockServer{})

		args := requiredArgs()
		args = append(args, "--"+secretLockKeyPathFlagName, file)

		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
	})

	t.Run("Fail with invalid secret-lock-key-path arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := requiredArgs()
		args = append(args, "--"+secretLockKeyPathFlagName, "invalid")

		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
	})
}

func TestStartCmdWithHubAuthURLParam(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	args := requiredArgs()
	args = append(args, "--"+hubAuthURLFlagName, "http://example.com")

	startCmd.SetArgs(args)

	err := startCmd.Execute()
	require.NoError(t, err)
}

func TestStartCmdWithEnableCORSParam(t *testing.T) {
	t.Run("Success with CORS enabled", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := requiredArgs()
		args = append(args, "--"+enableCORSFlagName, "true")

		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.NoError(t, err)
	})

	t.Run("Fail with invalid enable-cors param", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := requiredArgs()
		args = append(args, "--"+enableCORSFlagName, "invalid")

		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
	})
}

func TestStartCmdWithCacheExpirationParam(t *testing.T) {
	t.Run("Success with cache-expiration set", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := requiredArgs()
		args = append(args, "--"+cacheExpirationFlagName, "10m")

		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.NoError(t, err)
	})

	t.Run("Fail with invalid cache-expiration duration string", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := requiredArgs()
		args = append(args, "--"+cacheExpirationFlagName, "invalid")

		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
	})
}

func TestStartCmdWithJaegerURLParam(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	args := requiredArgs()
	args = append(args, "--"+jaegerURLFlagName, "http://example.com")

	startCmd.SetArgs(args)

	err := startCmd.Execute()
	require.NoError(t, err)
}

func TestStartKMSService(t *testing.T) {
	const invalidStorageOption = "invalid"

	t.Run("Success with default args", func(t *testing.T) {
		params := kmsRestParams(t)

		err := startKmsService(params, &mockServer{})
		require.NoError(t, err)
	})

	t.Run("Fail with invalid storage option", func(t *testing.T) {
		params := kmsRestParams(t)
		params.storageParams.storageType = invalidStorageOption

		err := startKmsService(params, &mockServer{})
		require.Error(t, err)
	})

	t.Run("Fail with invalid primary key storage option", func(t *testing.T) {
		params := kmsRestParams(t)
		params.primaryKeyStorageParams.storageType = invalidStorageOption

		err := startKmsService(params, &mockServer{})
		require.Error(t, err)
	})

	t.Run("Fail with invalid local kms storage option", func(t *testing.T) {
		params := kmsRestParams(t)
		params.localKMSStorageParams.storageType = invalidStorageOption

		err := startKmsService(params, &mockServer{})
		require.Error(t, err)
	})
}

func requiredArgs() []string {
	return []string{
		"--" + hostURLFlagName, "localhost:8080",
		"--" + databaseTypeFlagName, storageTypeMemOption,
		"--" + primaryKeyDatabaseTypeFlagName, storageTypeMemOption,
		"--" + localKMSDatabaseTypeFlagName, storageTypeMemOption,
		"--" + keyManagerStorageTypeFlagName, storageTypeMemOption,
	}
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

func kmsRestParams(t *testing.T) *kmsRestParameters {
	t.Helper()

	startCmd := GetStartCmd(&mockServer{})

	err := startCmd.ParseFlags(requiredArgs())
	require.NoError(t, err)

	params, err := getKmsRestParameters(startCmd)
	require.NotNil(t, params)
	require.NoError(t, err)

	return params
}

func setEnvVars(t *testing.T) {
	err := os.Setenv(hostURLEnvKey, "localhost:8080")
	require.NoError(t, err)

	err = os.Setenv(databaseTypeEnvKey, storageTypeMemOption)
	require.NoError(t, err)

	err = os.Setenv(primaryKeyDatabaseTypeEnvKey, storageTypeMemOption)
	require.NoError(t, err)

	err = os.Setenv(localKMSDatabaseTypeEnvKey, storageTypeMemOption)
	require.NoError(t, err)

	err = os.Setenv(keyManagerStorageTypeEnvKey, storageTypeMemOption)
	require.NoError(t, err)
}

func unsetEnvVars(t *testing.T) {
	err := os.Unsetenv(hostURLEnvKey)
	require.NoError(t, err)

	err = os.Unsetenv(databaseTypeEnvKey)
	require.NoError(t, err)

	err = os.Unsetenv(primaryKeyDatabaseTypeEnvKey)
	require.NoError(t, err)

	err = os.Unsetenv(localKMSDatabaseTypeEnvKey)
	require.NoError(t, err)

	err = os.Unsetenv(keyManagerStorageTypeEnvKey)
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

func createKeyFile(t *testing.T, empty bool) (string, func()) {
	t.Helper()

	f, err := ioutil.TempFile("", "secret-lock.key")
	require.NoError(t, err)

	closeFunc := func() {
		require.NoError(t, f.Close())
		require.NoError(t, os.Remove(f.Name()))
	}

	if empty {
		return f.Name(), closeFunc
	}

	key := make([]byte, sha256.Size)
	_, err = rand.Read(key)
	require.NoError(t, err)

	encodedKey := make([]byte, base64.URLEncoding.EncodedLen(len(key)))
	base64.URLEncoding.Encode(encodedKey, key)

	n, err := f.Write(encodedKey)
	require.NoError(t, err)
	require.Equal(t, len(encodedKey), n)

	return f.Name(), closeFunc
}
