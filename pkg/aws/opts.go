package aws

import (
	envutil "github.com/trustbloc/kms/pkg/env"
)

type opts struct {
	keyAliasPrefix string
}

func NewOpts() *opts {
	return &opts{
		keyAliasPrefix: envutil.StringEnvOpt("AWS_KEY_ALIAS_PREFIX", ""),
	}
}

func (o *opts) KeyAliasPrefix() string {
	return o.keyAliasPrefix
}

type Opts func(opts *opts)

func WithKeyAliasPrefix(prefix string) Opts {
	return func(opts *opts) { opts.keyAliasPrefix = prefix }
}
