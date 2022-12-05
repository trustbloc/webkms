//go:build unit
// +build unit

package envutil

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEnvUtil(t *testing.T) {

	t.Run("env: string var", func(t *testing.T) {
		var val string

		val = StringEnvOpt("STRING_ENVVAR", "default")
		require.Equal(t, "default", val)

		t.Setenv("STRING_ENVVAR", "env")

		val = StringEnvOpt("STRING_ENVVAR", "default")
		require.Equal(t, "env", val)
	})

	t.Run("env: int var ", func(t *testing.T) {
		var val int

		val = IntEnvOpt("INT_ENVVAR", 100)
		require.Equal(t, 100, val)

		t.Setenv("INT_ENVVAR", "1000")

		val = IntEnvOpt("INT_ENVVAR", 100)
		require.Equal(t, 1000, val)

		t.Setenv("INT_ENVVAR", "not an int")

		val = IntEnvOpt("INT_ENVVAR", 100)
		require.Equal(t, 100, val)
	})

	t.Run("env: bool var ", func(t *testing.T) {
		var val bool

		val = BoolEnvOpt("BOOL_ENVVAR", true)
		require.Equal(t, true, val)

		t.Setenv("BOOL_ENVVAR", "false")

		val = BoolEnvOpt("BOOL_ENVVAR", true)
		require.Equal(t, false, val)

		t.Setenv("BOOL_ENVVAR", "not a bool")

		val = BoolEnvOpt("BOOL_ENVVAR", true)
		require.Equal(t, true, val)
	})
}
