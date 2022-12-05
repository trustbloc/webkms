/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aws

import (
	"os"
)

type opts struct {
	keyAliasPrefix string
}

// NewOpts create new opts populated with environment variable.
func newOpts() *opts {
	value, _ := os.LookupEnv("AWS_KEY_ALIAS_PREFIX")

	return &opts{
		keyAliasPrefix: value,
	}
}

func (o *opts) KeyAliasPrefix() string {
	return o.keyAliasPrefix
}

// Opts a Functional Options.
type Opts func(opts *opts)

// WithKeyAliasPrefix sets the given prefix in the returns Opts.
func WithKeyAliasPrefix(prefix string) Opts {
	return func(opts *opts) { opts.keyAliasPrefix = prefix }
}
