/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package kms-rest KMS API.
//
//     Schemes: http
//     Version: 0.1.0
//     License: SPDX-License-Identifier: Apache-2.0
//
//     Consumes:
//     - application/json
//
//     Produces:
//     - application/json
//
// swagger:meta
package main

import (
	"github.com/spf13/cobra"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/hub-kms/cmd/kms-rest/startcmd"
)

func main() {
	rootCmd := &cobra.Command{
		Use: "kms-rest",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
		},
	}

	logger := log.New("kms-rest")
	server := startcmd.NewHTTPServer(logger)
	rootCmd.AddCommand(startcmd.GetStartCmd(server))

	if err := rootCmd.Execute(); err != nil {
		logger.Fatalf("Failed to run kms-rest: %s", err.Error())
	}
}
