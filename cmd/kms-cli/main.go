/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"github.com/spf13/cobra"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/kms/cmd/kms-cli/createkey"
	"github.com/trustbloc/kms/cmd/kms-cli/createkeystore"
)

var logger = log.New("kms-cli")

func main() {
	rootCmd := &cobra.Command{
		Use: "kms-cli",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
		},
	}

	keystore := &cobra.Command{
		Use: "keystore",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
		},
	}
	keystore.AddCommand(createkeystore.GetCmd())

	key := &cobra.Command{
		Use: "key",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
		},
	}

	key.AddCommand(createkey.GetCmd())

	rootCmd.AddCommand(keystore)
	rootCmd.AddCommand(key)

	if err := rootCmd.Execute(); err != nil {
		logger.Fatalf("Failed to run kms-cli: %s", err.Error())
	}
}
