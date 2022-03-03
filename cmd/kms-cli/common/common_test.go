/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package common //nolint:testpackage

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

type mockReq struct{}

type mockResp struct{}

func TestSendRequest(t *testing.T) {
	t.Run("test error 500", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))

		_, err := SendRequest(&http.Client{}, nil, map[string]string{}, http.MethodGet, serv.URL)
		require.Error(t, err)
		require.Contains(t, err.Error(), "got unexpected response from")
	})
}

func TestSendHTTPRequest(t *testing.T) {
	t.Run("test error 500", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))

		cmd := newMockCmd(func(cmd *cobra.Command, args []string) error {
			client, err := NewHTTPClient(cmd)
			if err != nil {
				return err
			}

			return SendHTTPRequest(client, &mockReq{}, NewAuthTokenHeader(cmd), http.MethodGet, serv.URL, &mockResp{})
		})

		cmd.SetArgs([]string{"--" + AuthTokenFlagName, "ADMIN_TOKEN"})

		err := cmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "got unexpected response from")
	})
}

func TestTLSSystemCertPoolInvalidArgsEnvVar(t *testing.T) {
	t.Run("test error 500", func(t *testing.T) {
		cmd := newMockCmd(func(cmd *cobra.Command, args []string) error {
			_, err := NewHTTPClient(cmd)

			return err
		})

		cmd.SetArgs([]string{"--" + AuthTokenFlagName, "ADMIN_TOKEN"})

		require.NoError(t, os.Setenv("KMS_CLI_TLS_SYSTEMCERTPOOL", "wrongvalue"))
		defer os.Clearenv()

		err := cmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid syntax")
	})
}

func TestUtils(t *testing.T) {
	t.Run("GetCreateKeystorePath", func(t *testing.T) {
		cmd := newMockCmd(func(cmd *cobra.Command, args []string) error {
			path, err := GetCreateKeystorePath(cmd)

			require.NoError(t, err)
			require.Equal(t, "test/v1/keystores", path)

			return nil
		})

		cmd.SetArgs([]string{"--url", "test"})
		err := cmd.Execute()
		require.NoError(t, err)
	})

	t.Run("GetCreateKeyPath", func(t *testing.T) {
		cmd := newMockCmd(func(cmd *cobra.Command, args []string) error {
			path, err := GetCreateKeyPath(cmd, "1234")

			require.NoError(t, err)
			require.Equal(t, "test/v1/keystores/1234/keys", path)

			return nil
		})

		cmd.SetArgs([]string{"--url", "test"})
		err := cmd.Execute()
		require.NoError(t, err)
	})
}

func newMockCmd(runFUnc func(cmd *cobra.Command, args []string) error) *cobra.Command {
	cmd := &cobra.Command{
		Use:  "mock",
		RunE: runFUnc,
	}

	AddCommonFlags(cmd)

	return cmd
}
