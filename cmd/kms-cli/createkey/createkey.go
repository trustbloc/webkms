/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package createkey

import (
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/spf13/cobra"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"

	"github.com/trustbloc/kms/cmd/kms-cli/common"
)

const (
	keystoreFlagName  = "keystore"
	keystoreFlagUsage = "Keystore ID. " +
		" Alternatively, this can be set with the following environment variable: " + keystoreEnvKey
	keystoreEnvKey = "KMS_CLI_KEYSTORE_ID"

	typeFlagName  = "type"
	typeFlagUsage = "Creating keys type. " +
		" Alternatively, this can be set with the following environment variable: " + typeEnvKey
	typeEnvKey = "KMS_KEY_TYPE"
)

type createKeyReq struct {
	KeyType   string `json:"key_type"`
	ExportKey bool   `json:"export"`
}

type createKeyResp struct {
	KeyURL    string `json:"key_url"`
	PublicKey []byte `json:"public_key"`
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

			keystoreID, err := cmdutils.GetUserSetVarFromString(cmd, keystoreFlagName,
				keystoreEnvKey, false)
			if err != nil {
				return err
			}

			keyType, err := cmdutils.GetUserSetVarFromString(cmd, typeFlagName,
				typeEnvKey, false)
			if err != nil {
				return err
			}

			createKeyPath, err := common.GetCreateKeyPath(cmd, keystoreID)
			if err != nil {
				return err
			}

			request := &createKeyReq{
				KeyType:   keyType,
				ExportKey: true,
			}

			response := &createKeyResp{}

			err = common.SendHTTPRequest(httpClient, request, common.NewAuthTokenHeader(cmd), http.MethodPost,
				createKeyPath, response)

			if err != nil {
				return err
			}

			fmt.Printf("keyURL=%s\n", response.KeyURL)
			if len(response.PublicKey) > 0 {
				fmt.Printf("%s\n", base64.StdEncoding.EncodeToString(response.PublicKey))
			}

			return nil
		},
	}
}

func createFlags(startCmd *cobra.Command) {
	common.AddCommonFlags(startCmd)

	startCmd.Flags().StringP(keystoreFlagName, "", "", keystoreFlagUsage)
	startCmd.Flags().StringP(typeFlagName, "", "", typeFlagUsage)
}
