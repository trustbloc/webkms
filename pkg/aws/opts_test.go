//go:build unit
// +build unit

package aws

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOpts(t *testing.T) {
	t.Run("options: defaults", func(t *testing.T) {
		options := NewOpts()

		require.Equal(t, "", options.KeyAliasPrefix())
	})

	t.Run("options: set manually", func(t *testing.T) {
		options := NewOpts()

		WithKeyAliasPrefix("keyaliasprefix")(options)

		require.Equal(t, "keyaliasprefix", options.KeyAliasPrefix())
	})

	t.Run("options: env vars", func(t *testing.T) {
		t.Setenv("AWS_KEY_ALIAS_PREFIX", "keyaliasprefix")

		options := NewOpts()

		require.Equal(t, "keyaliasprefix", options.KeyAliasPrefix())
	})
}
