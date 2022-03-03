/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package createkeystore //nolint:testpackage

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTLSSystemCertPoolInvalidArgsEnvVar(t *testing.T) {
	startCmd := GetCmd()

	startCmd.SetArgs([]string{
		"--url", "someurl",
		"--controller", "did:example:12345",
	})

	require.NoError(t, os.Setenv("KMS_CLI_TLS_SYSTEMCERTPOOL", "wrongvalue"))
	defer os.Clearenv()

	err := startCmd.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid syntax")
}

func TestStartCmdWithMissingArg(t *testing.T) {
	t.Run("test missing url arg", func(t *testing.T) {
		startCmd := GetCmd()

		err := startCmd.Execute()

		require.Error(t, err)
		require.Equal(t,
			"Neither url (command line flag) nor KMS_CLI_URL (environment variable) have been set.",
			err.Error())
	})

	t.Run("test missing controller arg", func(t *testing.T) {
		startCmd := GetCmd()

		startCmd.SetArgs([]string{
			"--url", "someurl",
		})

		err := startCmd.Execute()

		require.Error(t, err)
		require.Equal(t,
			"Neither controller (command line flag) nor KMS_CLI_CONTROLLER (environment variable) have been set.",
			err.Error())
	})
}

func TestCreateKeystore(t *testing.T) {
	serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := fmt.Fprint(w, "{\"key_store_url\":\"test\"}")
		require.NoError(t, err)
	}))

	t.Run("test failed to follow", func(t *testing.T) {
		os.Clearenv()
		cmd := GetCmd()

		cmd.SetArgs([]string{
			"--url", "https://localhost:8080",
			"--controller", "did:example:12345",
		})

		err := cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to send request")
	})

	t.Run("success", func(t *testing.T) {
		cmd := GetCmd()

		cmd.SetArgs([]string{
			"--url", serv.URL,
			"--controller", "did:example:12345",
		})

		err := cmd.Execute()

		require.NoError(t, err)
	})
}
