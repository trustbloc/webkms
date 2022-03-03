/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package createkey //nolint:testpackage

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStartCmdWithMissingArg(t *testing.T) {
	t.Run("test missing keystore arg", func(t *testing.T) {
		startCmd := GetCmd()

		err := startCmd.Execute()

		require.Error(t, err)
		require.Equal(t,
			"Neither keystore (command line flag) nor KMS_CLI_KEYSTORE_ID (environment variable) have been set.",
			err.Error())
	})

	t.Run("test missing url arg", func(t *testing.T) {
		startCmd := GetCmd()

		startCmd.SetArgs([]string{
			"--keystore", "some_id",
			"--type", "ED25519",
		})

		err := startCmd.Execute()

		require.Error(t, err)
		require.Equal(t,
			"Neither url (command line flag) nor KMS_CLI_URL (environment variable) have been set.",
			err.Error())
	})

	t.Run("test missing url arg", func(t *testing.T) {
		startCmd := GetCmd()

		startCmd.SetArgs([]string{
			"--keystore", "some_id",
			"--type", "ED25519",
		})

		err := startCmd.Execute()

		require.Error(t, err)
		require.Equal(t,
			"Neither url (command line flag) nor KMS_CLI_URL (environment variable) have been set.",
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
			"--keystore", "some_id",
			"--type", "ED25519",
		})

		err := cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to send request")
	})

	t.Run("success", func(t *testing.T) {
		cmd := GetCmd()

		cmd.SetArgs([]string{
			"--url", serv.URL,
			"--keystore", "some_id",
			"--type", "ED25519",
		})

		err := cmd.Execute()

		require.NoError(t, err)
	})
}
