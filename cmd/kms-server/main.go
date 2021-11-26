/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package kms-server for key management and crypto operations.
//
//     Schemes: http
//     Version: 0.1.8
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
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/spf13/cobra"

	"github.com/trustbloc/kms/cmd/kms-server/startcmd"
)

var logger = log.New("kms-server")

func main() {
	rootCmd := &cobra.Command{
		Use: "kms-server",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
		},
	}

	startCmd, err := startcmd.Cmd(&startcmd.HTTPServer{})
	if err != nil {
		logger.Fatalf(err.Error())
	}

	rootCmd.AddCommand(startCmd)

	if err := rootCmd.Execute(); err != nil {
		logger.Fatalf("Failed to run kms-server: %v", err)
	}
}
