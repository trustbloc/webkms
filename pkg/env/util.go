package envutil

import (
	"os"
	"strconv"

	"github.com/trustbloc/edge-core/pkg/log"
)

var logger = log.New("envutil")

func StringEnvOpt(env, def string) string {
	return envOpt(env, def, func(v string) (string, error) { return v, nil })
}

func IntEnvOpt(env string, def int) int {
	return envOpt(env, def, strconv.Atoi)
}

func BoolEnvOpt(env string, def bool) bool {
	return envOpt(env, def, strconv.ParseBool)
}

func envOpt[T any](env string, def T, parse func(string) (T, error)) T {
	if opt, set := os.LookupEnv(env); set {
		val, err := parse(opt)
		if err != nil {
			logger.Warnf("cannot parse %s ENV var, continuing with default %+v. err = %v", env, def, err)

			return def
		}

		return val
	}

	return def
}
