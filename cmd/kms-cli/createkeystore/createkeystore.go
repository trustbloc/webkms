/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package createkeystore

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/spf13/cobra"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"

	"github.com/trustbloc/kms/cmd/kms-cli/common"
)

const (
	controllerFlagName  = "controller"
	controllerFlagUsage = "Keystore controller. " +
		" Alternatively, this can be set with the following environment variable: " + controllerEnvKey
	controllerEnvKey = "KMS_CLI_CONTROLLER"
)

type createKeystoreReq struct {
	Controller string      `json:"controller"`
	EDV        *edvOptions `json:"edv"`
}

type edvOptions struct {
	VaultURL   string `json:"vault_url"`
	Capability []byte `json:"capability"`
}

type createKeyStoreResp struct {
	KeyStoreURL string `json:"key_store_url"`
	Capability  []byte `json:"capability"`
}

// GetCmd returns the Cobra follow command.
func GetCmd() *cobra.Command {
	createCmd := createCmd()

	createFlags(createCmd)

	return createCmd
}

func createCmd() *cobra.Command {
	return &cobra.Command{
		Use:          "create",
		Short:        "create keystore",
		Long:         "create keystore",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			httpClient, err := common.NewHTTPClient(cmd)
			if err != nil {
				return err
			}

			createKeystorePath, err := common.GetCreateKeystorePath(cmd)
			if err != nil {
				return err
			}

			controller, err := cmdutils.GetUserSetVarFromString(cmd, controllerFlagName,
				controllerEnvKey, false)
			if err != nil {
				return err
			}

			request := &createKeystoreReq{
				Controller: controller,
			}

			response := &createKeyStoreResp{}

			err = common.SendHTTPRequest(httpClient, request, common.NewAuthTokenHeader(cmd), http.MethodPost,
				createKeystorePath, response)

			if err != nil {
				return err
			}

			parts := strings.Split(response.KeyStoreURL, "/")
			if len(parts) > 0 {
				fmt.Printf("keystore=%s", parts[len(parts)-1])
			} else {
				fmt.Printf("invalid response from the server")
			}

			return nil
		},
	}
}

func createFlags(startCmd *cobra.Command) {
	common.AddCommonFlags(startCmd)

	startCmd.Flags().StringP(controllerFlagName, "", "", controllerFlagUsage)
}
