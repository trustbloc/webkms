/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd //nolint:testpackage

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io/ioutil"
	"net/http"
	"os"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/mock/storage"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/common/log/mocklogger"
	logspi "github.com/hyperledger/aries-framework-go/spi/log"
	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

const (
	logLevelCritical = "critical"
	logLevelError    = "error"
	logLevelWarn     = "warning"
	logLevelInfo     = "info"
	logLevelDebug    = "debug"
)

var (
	secretLockKeyFile  string
	gnapSigningKeyFile string
)

type mockServer struct{}

func (s *mockServer) ListenAndServe(host, certFile, keyFile string, router http.Handler) error {
	return nil
}

func (s *mockServer) Logger() logspi.Logger {
	return &mocklogger.MockLogger{}
}

func TestListenAndServe(t *testing.T) {
	t.Run("test wrong host", func(t *testing.T) {
		var w HTTPServer
		err := w.ListenAndServe("wronghost", "", "", nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "address wronghost: missing port in address")
	})

	t.Run("test invalid key file", func(t *testing.T) {
		var w HTTPServer
		err := w.ListenAndServe("localhost:8080", "test.key", "test.cert", nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "open test.key: no such file or directory")
	})
}

func TestStartCmdContents(t *testing.T) {
	startCmd, err := Cmd(&mockServer{})

	require.NoError(t, err)
	require.Equal(t, "start", startCmd.Use)
	require.Equal(t, "Starts kms-server", startCmd.Short)
	require.Equal(t, "Starts server for handling key management and crypto operations", startCmd.Long)

	checkFlagPropertiesCorrect(t, startCmd, hostFlagName, "", hostFlagUsage)
}

func TestStartCmdWithMissingArg(t *testing.T) {
	t.Run("test missing database-type arg", func(t *testing.T) {
		startCmd, err := Cmd(&mockServer{})
		require.NoError(t, err)

		args := []string{
			"--" + secretLockTypeFlagName, secretLockTypeLocalOption,
		}
		startCmd.SetArgs(args)

		err = startCmd.Execute()
		require.Error(t, err)
		require.Equal(t, "get parameters: neither database-type (command line flag) nor "+
			"KMS_DATABASE_TYPE (environment variable) have been set",
			err.Error())
	})

	t.Run("test missing secret-lock-type arg", func(t *testing.T) {
		startCmd, err := Cmd(&mockServer{})
		require.NoError(t, err)

		args := []string{
			"--" + databaseTypeFlagName, storageTypeMemOption,
		}
		startCmd.SetArgs(args)

		err = startCmd.Execute()

		require.Error(t, err)
		require.Equal(t, "get parameters: neither secret-lock-type (command line flag) nor "+
			"KMS_SECRET_LOCK_TYPE (environment variable) have been set",
			err.Error())
	})

	t.Run("test missing auth-server-url when gnap is enabled", func(t *testing.T) {
		startCmd, err := Cmd(&mockServer{})
		require.NoError(t, err)

		args := []string{
			"--" + databaseTypeFlagName, storageTypeMemOption,
			"--" + secretLockTypeFlagName, secretLockTypeLocalOption,
			"--" + secretLockKeyPathFlagName, secretLockKeyFile,
			"--" + gnapSigningKeyPathFlagName, gnapSigningKeyFile,
		}
		startCmd.SetArgs(args)

		err = startCmd.Execute()
		require.Error(t, err)
		require.Equal(t, "create gnap rs client: gnap introspect client: missing Resource Server URL", err.Error())
	})
}

func TestStartCmdValidArgs(t *testing.T) {
	t.Run("using in-memory storage option", func(t *testing.T) {
		startCmd, err := Cmd(&mockServer{})
		require.NoError(t, err)

		startCmd.SetArgs(requiredArgs(storageTypeMemOption))

		err = startCmd.Execute()
		require.Nil(t, err)
	})
	t.Run("using MongoDB storage option", func(t *testing.T) {
		pool, mongoDBResource := startMongoDBContainer(t)

		defer func() {
			require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
		}()

		startCmd, err := Cmd(&mockServer{})
		require.NoError(t, err)
		startCmd.SetArgs(requiredArgs(storageTypeMongoDBOption))

		err = startCmd.Execute()
		require.Nil(t, err)
	})
}

func startMongoDBContainer(t *testing.T) (*dctest.Pool, *dctest.Resource) {
	t.Helper()

	pool, err := dctest.NewPool("")
	require.NoError(t, err)

	mongoDBResource, err := pool.RunWithOptions(&dctest.RunOptions{
		Repository: "mongo",
		Tag:        "4.0.0",
		PortBindings: map[dc.Port][]dc.PortBinding{
			"27017/tcp": {{HostIP: "", HostPort: "27017"}},
		},
	})
	require.NoError(t, err)

	return pool, mongoDBResource
}

func TestStartCmdValidArgsEnvVar(t *testing.T) {
	startCmd, err := Cmd(&mockServer{})
	require.NoError(t, err)

	setEnvVars(t)
	defer unsetEnvVars(t)

	err = startCmd.Execute()
	require.NoError(t, err)
}

func TestStartCmdLogLevels(t *testing.T) {
	tests := []struct {
		desc string
		in   string
		out  logspi.Level
	}{
		{`Log level not specified - defaults to "info"`, "", logspi.INFO},
		{"Log level: critical", logLevelCritical, logspi.CRITICAL},
		{"Log level: error", logLevelError, logspi.ERROR},
		{"Log level: warn", logLevelWarn, logspi.WARNING},
		{"Log level: info", logLevelInfo, logspi.INFO},
		{"Log level: debug", logLevelDebug, logspi.DEBUG},
		{"Invalid log level - defaults to info", "invalid log level", logspi.INFO},
	}

	for _, tt := range tests {
		startCmd, err := Cmd(&mockServer{})
		require.NoError(t, err)

		args := requiredArgs(storageTypeMemOption)

		if tt.in != "" {
			args = append(args, "--"+logLevelFlagName, tt.in)
		}

		startCmd.SetArgs(args)
		err = startCmd.Execute()

		require.Nil(t, err)
		require.Equal(t, tt.out, log.GetLevel(""))
	}
}

func TestStartCmdWithTLSCertParams(t *testing.T) {
	t.Run("Success with tls-systemcertpool arg", func(t *testing.T) {
		startCmd, err := Cmd(&mockServer{})
		require.NoError(t, err)

		args := requiredArgs(storageTypeMemOption)
		args = append(args, "--"+tlsSystemCertPoolFlagName, "true")

		startCmd.SetArgs(args)

		err = startCmd.Execute()
		require.Nil(t, err)
	})

	t.Run("Fail with invalid tls-systemcertpool arg", func(t *testing.T) {
		startCmd, err := Cmd(&mockServer{})
		require.NoError(t, err)

		args := requiredArgs(storageTypeMemOption)
		args = append(args, "--"+tlsSystemCertPoolFlagName, "invalid")

		startCmd.SetArgs(args)

		err = startCmd.Execute()
		require.Error(t, err)
	})

	t.Run("Failed to read cert", func(t *testing.T) {
		startCmd, err := Cmd(&mockServer{})
		require.NoError(t, err)

		args := requiredArgs(storageTypeMemOption)
		args = append(args, "--"+tlsCACertsFlagName, "/test/path")

		startCmd.SetArgs(args)

		err = startCmd.Execute()
		require.Contains(t, err.Error(), "failed to read cert: open /test/path")
	})
}

func TestStartCmdWithSecretLockKeyPathParam(t *testing.T) {
	t.Run("Success with valid key file", func(t *testing.T) {
		startCmd, err := Cmd(&mockServer{})
		require.NoError(t, err)

		args := requiredArgs(storageTypeMemOption)
		args = append(args, "--"+secretLockKeyPathFlagName, secretLockKeyFile)

		startCmd.SetArgs(args)

		err = startCmd.Execute()
		require.NoError(t, err)
	})

	t.Run("Fail with invalid key file content", func(t *testing.T) {
		f, err := ioutil.TempFile("", "empty-secret-lock.key")
		require.NoError(t, err)

		defer func() {
			require.NoError(t, f.Close())
			require.NoError(t, os.Remove(f.Name()))
		}()

		startCmd, err := Cmd(&mockServer{})
		require.NoError(t, err)

		args := requiredArgs(storageTypeMemOption)
		args = append(args, "--"+secretLockKeyPathFlagName, f.Name())

		startCmd.SetArgs(args)

		err = startCmd.Execute()
		require.Error(t, err)
	})

	t.Run("Fail with invalid secret-lock-key-path arg", func(t *testing.T) {
		startCmd, err := Cmd(&mockServer{})
		require.NoError(t, err)

		args := requiredArgs(storageTypeMemOption)
		args = append(args, "--"+secretLockKeyPathFlagName, "invalid")

		startCmd.SetArgs(args)

		err = startCmd.Execute()
		require.Error(t, err)
	})
}

func TestStartCmdWithAWSSecretLockParam(t *testing.T) {
	const keyURI = "aws-kms://arn:aws:kms:ca-central-1:111122223333:key/bc436485-5092-42b8-92a3-0aa8b93536dc"

	t.Run("Success with valid aws", func(t *testing.T) {
		startCmd, err := Cmd(&mockServer{})
		require.NoError(t, err)

		args := requiredArgsWithLockType(storageTypeMemOption, secretLockTypeAWSOption)
		args = append(args, "--"+secretLockAWSKeyURIFlagName, keyURI,
			"--"+secretLockAWSAccessKeyFlagName, "key",
			"--"+secretLockAWSSecretKeyFlagName, "secret-key")

		startCmd.SetArgs(args)

		err = startCmd.Execute()
		require.NoError(t, err)
	})

	t.Run("Fail with invalid aws key uri", func(t *testing.T) {
		startCmd, err := Cmd(&mockServer{})
		require.NoError(t, err)

		args := requiredArgsWithLockType(storageTypeMemOption, secretLockTypeAWSOption)
		args = append(args, "--"+secretLockAWSKeyURIFlagName, "invalid-uri",
			"--"+secretLockAWSAccessKeyFlagName, "key",
			"--"+secretLockAWSSecretKeyFlagName, "secret-key")

		startCmd.SetArgs(args)

		err = startCmd.Execute()
		require.Error(t, err)
	})
}

func TestStartCmdWithHubAuthURLParam(t *testing.T) {
	startCmd, err := Cmd(&mockServer{})
	require.NoError(t, err)

	args := requiredArgs(storageTypeMemOption)
	args = append(args, "--"+authServerURLFlagName, "http://example.com")

	startCmd.SetArgs(args)

	err = startCmd.Execute()
	require.NoError(t, err)
}

func TestStartCmdWithEnableCORSParam(t *testing.T) {
	t.Run("Success with CORS enabled", func(t *testing.T) {
		startCmd, err := Cmd(&mockServer{})
		require.NoError(t, err)

		args := requiredArgs(storageTypeMemOption)
		args = append(args, "--"+enableCORSFlagName, "true")

		startCmd.SetArgs(args)

		err = startCmd.Execute()
		require.NoError(t, err)
	})

	t.Run("Fail with invalid enable-cors param", func(t *testing.T) {
		startCmd, err := Cmd(&mockServer{})
		require.NoError(t, err)

		args := requiredArgs(storageTypeMemOption)
		args = append(args, "--"+enableCORSFlagName, "invalid")

		startCmd.SetArgs(args)

		err = startCmd.Execute()
		require.Error(t, err)
	})
}

func TestStartCmdWithEnableCacheParam(t *testing.T) {
	t.Run("Success with cache enabled", func(t *testing.T) {
		startCmd, err := Cmd(&mockServer{})
		require.NoError(t, err)

		args := requiredArgs(storageTypeMemOption)
		args = append(args, "--"+enableCacheFlagName, "true")

		startCmd.SetArgs(args)

		err = startCmd.Execute()
		require.NoError(t, err)
	})

	t.Run("Fail with invalid enable-cache param", func(t *testing.T) {
		startCmd, err := Cmd(&mockServer{})
		require.NoError(t, err)

		args := requiredArgs(storageTypeMemOption)
		args = append(args, "--"+enableCacheFlagName, "invalid")

		startCmd.SetArgs(args)

		err = startCmd.Execute()
		require.Error(t, err)
	})
}

func TestStartCmdWithKeyStoreCacheTTLParam(t *testing.T) {
	t.Run("Success with key-store-cache-ttl set", func(t *testing.T) {
		startCmd, err := Cmd(&mockServer{})
		require.NoError(t, err)

		args := requiredArgs(storageTypeMemOption)
		args = append(args, "--"+keyStoreCacheTTLFlagName, "10m")

		startCmd.SetArgs(args)

		err = startCmd.Execute()
		require.NoError(t, err)
	})

	t.Run("Fail with invalid key-store-cache-ttl duration string", func(t *testing.T) {
		startCmd, err := Cmd(&mockServer{})
		require.NoError(t, err)

		args := requiredArgs(storageTypeMemOption)
		args = append(args, "--"+keyStoreCacheTTLFlagName, "invalid")

		startCmd.SetArgs(args)

		err = startCmd.Execute()
		require.Error(t, err)
	})
}

func TestStartCmdWithShamirCacheTTLParam(t *testing.T) {
	t.Run("Success with shamir-secret-cache-ttl set", func(t *testing.T) {
		startCmd, err := Cmd(&mockServer{})
		require.NoError(t, err)

		args := requiredArgs(storageTypeMemOption)
		args = append(args, "--"+shamirSecretCacheTTLFlagName, "10m")

		startCmd.SetArgs(args)

		err = startCmd.Execute()
		require.NoError(t, err)
	})

	t.Run("Fail with invalid shamir-secret-cache-ttl duration string", func(t *testing.T) {
		startCmd, err := Cmd(&mockServer{})
		require.NoError(t, err)

		args := requiredArgs(storageTypeMemOption)
		args = append(args, "--"+shamirSecretCacheTTLFlagName, "invalid")

		startCmd.SetArgs(args)

		err = startCmd.Execute()
		require.Error(t, err)
	})
}

func TestStartCmdWithKMSCacheTTLParam(t *testing.T) {
	t.Run("Success with kms-cache-ttl set", func(t *testing.T) {
		startCmd, err := Cmd(&mockServer{})
		require.NoError(t, err)

		args := requiredArgs(storageTypeMemOption)
		args = append(args, "--"+kmsCacheTTLFlagName, "10m")

		startCmd.SetArgs(args)

		err = startCmd.Execute()
		require.NoError(t, err)
	})

	t.Run("Fail with invalid kms-cache-ttl duration string", func(t *testing.T) {
		startCmd, err := Cmd(&mockServer{})
		require.NoError(t, err)

		args := requiredArgs(storageTypeMemOption)
		args = append(args, "--"+kmsCacheTTLFlagName, "invalid")

		startCmd.SetArgs(args)

		err = startCmd.Execute()
		require.Error(t, err)
	})

	t.Run("Fail with zero kms-cache-ttl duration string", func(t *testing.T) {
		startCmd, err := Cmd(&mockServer{})
		require.NoError(t, err)

		args := requiredArgs(storageTypeMemOption)
		args = append(args, "--"+kmsCacheTTLFlagName, "0s")
		args = append(args, "--"+enableCacheFlagName, "true")

		startCmd.SetArgs(args)

		err = startCmd.Execute()
		require.Error(t, err)
	})
}

func TestStartKMSService(t *testing.T) {
	const invalidStorageOption = "invalid"

	t.Run("Success with default args", func(t *testing.T) {
		params := kmsServerParams(t)

		err := startServer(&mockServer{}, params)
		require.NoError(t, err)
	})

	t.Run("Fail with invalid storage option", func(t *testing.T) {
		params := kmsServerParams(t)
		params.databaseType = invalidStorageOption

		err := startServer(&mockServer{}, params)
		require.Error(t, err)
	})
}

func TestStartMetrics(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		srv := &mockServer{}

		startMetrics(srv, "localhost:8081")

		logger, ok := srv.Logger().(*mocklogger.MockLogger)
		require.True(t, ok)
		require.Empty(t, logger.FatalLogContents)
	})
}

func TestCreateKMS(t *testing.T) {
	mockStoreProvider := &storage.MockStoreProvider{
		FailNamespace: kms.AriesWrapperStoreName,
		Store: &storage.MockStore{
			Store: map[string]storage.DBEntry{},
		},
	}

	lockKeyFile, lockKeyFileClose := createSecretLockKeyFile()

	defer lockKeyFileClose()

	keyManager, err := createKMS(mockStoreProvider, &secretLockParameters{
		secretLockType: secretLockTypeLocalOption,
		localKeyPath:   lockKeyFile,
	})
	require.EqualError(t, err, "failed to open store for name space kmsdb")
	require.Nil(t, keyManager)
}

func requiredArgs(databaseType string) []string {
	return requiredArgsWithLockType(databaseType, secretLockTypeLocalOption)
}

func requiredArgsWithLockType(databaseType, lockType string) []string {
	args := []string{
		"--" + hostFlagName, "localhost:8080",
		"--" + databaseTypeFlagName, databaseType,
		"--" + secretLockTypeFlagName, lockType,
		"--" + gnapSigningKeyPathFlagName, gnapSigningKeyFile,
		"--" + authServerURLFlagName, "http://example.com",
	}

	if lockType == secretLockTypeLocalOption {
		args = append(args,
			"--"+secretLockKeyPathFlagName, secretLockKeyFile)
	}

	if databaseType == storageTypeMongoDBOption {
		args = append(args,
			"--"+databaseURLFlagName, "mongodb://localhost:27017")
	}

	return args
}

func kmsServerParams(t *testing.T) *serverParameters {
	t.Helper()

	startCmd, err := Cmd(&mockServer{})
	require.NoError(t, err)

	err = startCmd.ParseFlags(requiredArgs(storageTypeMemOption))
	require.NoError(t, err)

	params, err := getParameters(startCmd)
	require.NotNil(t, params)
	require.NoError(t, err)

	return params
}

func setEnvVars(t *testing.T) {
	t.Helper()

	err := os.Setenv(hostEnvKey, "localhost:8080")
	require.NoError(t, err)

	err = os.Setenv(databaseTypeEnvKey, storageTypeMemOption)
	require.NoError(t, err)

	err = os.Setenv(secretLockTypeEnvKey, secretLockTypeLocalOption)
	require.NoError(t, err)

	err = os.Setenv(secretLockKeyPathEnvKey, secretLockKeyFile)
	require.NoError(t, err)

	err = os.Setenv(disableAuthEnvKey, "true")
	require.NoError(t, err)
}

func unsetEnvVars(t *testing.T) {
	t.Helper()

	err := os.Unsetenv(hostEnvKey)
	require.NoError(t, err)

	err = os.Unsetenv(databaseTypeEnvKey)
	require.NoError(t, err)

	err = os.Unsetenv(secretLockTypeEnvKey)
	require.NoError(t, err)

	err = os.Unsetenv(secretLockKeyPathEnvKey)
	require.NoError(t, err)

	err = os.Unsetenv(disableAuthEnvKey)
	require.NoError(t, err)
}

func checkFlagPropertiesCorrect(t *testing.T, cmd *cobra.Command, flagName, flagShorthand, flagUsage string) {
	t.Helper()

	flag := cmd.Flag(flagName)

	require.NotNil(t, flag)
	require.Equal(t, flagName, flag.Name)
	require.Equal(t, flagShorthand, flag.Shorthand)
	require.Equal(t, flagUsage, flag.Usage)
	require.Equal(t, "", flag.Value.String())

	flagAnnotations := flag.Annotations
	require.Nil(t, flagAnnotations)
}

func TestMain(m *testing.M) {
	lockKeyFile, lockKeyFileClose := createSecretLockKeyFile()
	secretLockKeyFile = lockKeyFile

	gnapKeyFile, gnapKeyFileClose := createGNAPSigningKeyFile()
	gnapSigningKeyFile = gnapKeyFile

	code := m.Run()

	lockKeyFileClose()
	gnapKeyFileClose()

	os.Exit(code)
}

func createSecretLockKeyFile() (string, func()) {
	f, err := ioutil.TempFile("", "secret-lock.key")
	if err != nil {
		panic(err)
	}

	closeFunc := func() {
		if closeErr := f.Close(); closeErr != nil {
			panic(closeErr)
		}

		if removeErr := os.Remove(f.Name()); removeErr != nil {
			panic(removeErr)
		}
	}

	key := make([]byte, sha256.Size)
	_, err = rand.Read(key)
	if err != nil {
		panic(err)
	}

	encodedKey := make([]byte, base64.URLEncoding.EncodedLen(len(key)))
	base64.URLEncoding.Encode(encodedKey, key)

	_, err = f.Write(encodedKey)
	if err != nil {
		panic(err)
	}

	return f.Name(), closeFunc
}

func createGNAPSigningKeyFile() (string, func()) {
	f, err := ioutil.TempFile("", "gnap-priv-key.pem")
	if err != nil {
		panic(err)
	}

	closeFunc := func() {
		if closeErr := f.Close(); closeErr != nil {
			panic(closeErr)
		}

		if removeErr := os.Remove(f.Name()); removeErr != nil {
			panic(removeErr)
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		panic(err)
	}

	b := pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	}

	if err = pem.Encode(f, &b); err != nil {
		panic(err)
	}

	return f.Name(), closeFunc
}
