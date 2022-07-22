/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bdd_test

import (
	"flag"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cucumber/godog"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"

	"github.com/trustbloc/kms/test/bdd/pkg/cli"
	"github.com/trustbloc/kms/test/bdd/pkg/common"
	"github.com/trustbloc/kms/test/bdd/pkg/context"
	"github.com/trustbloc/kms/test/bdd/pkg/gnap"
	"github.com/trustbloc/kms/test/bdd/pkg/keystore"
	"github.com/trustbloc/kms/test/bdd/pkg/kms"
)

const (
	featuresPath    = "features"
	caCertPath      = "./fixtures/keys/tls/ec-cacert.pem"
	composeDir      = "./fixtures/"
	composeFilePath = composeDir + "docker-compose.yml"
)

var logger = log.New("kms/bdd")

func TestMain(m *testing.M) {
	// default is to run all tests with tag @all but excluding those marked with @wip
	tags := "all && ~@wip"

	if os.Getenv("TAGS") != "" {
		tags = os.Getenv("TAGS")
	}

	flag.Parse()

	format := "progress"
	if getCmdArg("test.v") == "true" { //nolint:goconst
		format = "pretty"
	}

	runArg := getCmdArg("test.run")
	if runArg != "" {
		tags = runArg
	}

	status := runBDDTests(tags, format)
	if st := m.Run(); st > status {
		status = st
	}

	os.Exit(status)
}

func getCmdArg(argName string) string {
	cmdTags := flag.CommandLine.Lookup(argName)
	if cmdTags != nil && cmdTags.Value != nil && cmdTags.Value.String() != "" {
		return cmdTags.Value.String()
	}

	return ""
}

func runBDDTests(tags, format string) int {
	return godog.TestSuite{
		Name:                 "kms test suite",
		TestSuiteInitializer: initializeTestSuite,
		ScenarioInitializer:  initializeScenario,
		Options:              buildOptions(tags, format),
	}.Run()
}

func initializeTestSuite(ctx *godog.TestSuiteContext) {
	var (
		dockerComposeUp   = []string{"docker-compose", "-f", composeFilePath, "up", "--force-recreate", "-d"}
		dockerComposeDown = []string{"docker-compose", "-f", composeFilePath, "down"}
	)

	compose := os.Getenv("DISABLE_COMPOSITION") != "true"

	ctx.BeforeSuite(func() {
		if compose { //nolint:nestif
			logger.Infof("Running %s", strings.Join(dockerComposeUp, " "))

			cmd := exec.Command(dockerComposeUp[0], dockerComposeUp[1:]...) //nolint:gosec // ignore G204
			if out, err := cmd.CombinedOutput(); err != nil {
				logger.Fatalf("%s: %s", err.Error(), string(out))
			}

			testSleep := 30
			if os.Getenv("TEST_SLEEP") != "" {
				s, err := strconv.Atoi(os.Getenv("TEST_SLEEP"))
				if err != nil {
					logger.Errorf("invalid 'TEST_SLEEP' value: %w", err)
				} else {
					testSleep = s
				}
			}

			logger.Infof("*** testSleep=%d\n\n", testSleep)
			time.Sleep(time.Second * time.Duration(testSleep))
		}
	})

	ctx.AfterSuite(func() {
		if compose {
			logger.Infof("Running %s", strings.Join(dockerComposeDown, " "))

			cmd := exec.Command(dockerComposeDown[0], dockerComposeDown[1:]...) //nolint:gosec // ignore G204
			if out, err := cmd.CombinedOutput(); err != nil {
				logger.Fatalf("%s: %s", err.Error(), string(out))
			}
		}
	})
}

type feature interface {
	// SetContext is called before every scenario is run with a fresh new context.
	SetContext(*context.BDDContext)
	// RegisterSteps is invoked once to register the steps on the suite.
	RegisterSteps(ctx *godog.ScenarioContext)
}

func initializeScenario(ctx *godog.ScenarioContext) {
	caCertPathVal := caCertPath
	if os.Getenv("DISABLE_CUSTOM_CA") == "true" {
		caCertPathVal = ""
	}

	bddContext, err := context.NewBDDContext(caCertPathVal)
	if err != nil {
		logger.Fatalf("Failed to create a new BDD context: %s", err.Error())
	}

	gnapSteps, err := gnap.NewSteps(bddContext.TLSConfig())
	if err != nil {
		logger.Fatalf("Failed to create gnap steps: %s", err.Error())
	}

	features := []feature{
		common.NewSteps(),
		keystore.NewSteps(),
		kms.NewSteps(bddContext.TLSConfig()),
		gnapSteps,
		cli.NewCLISteps(),
	}

	for _, f := range features {
		f.RegisterSteps(ctx)
	}

	ctx.BeforeScenario(func(sc *godog.Scenario) {
		for _, f := range features {
			f.SetContext(bddContext)
		}
	})
}

func buildOptions(tags, format string) *godog.Options {
	return &godog.Options{
		Tags:          tags,
		Format:        format,
		Paths:         []string{featuresPath},
		Strict:        true,
		StopOnFailure: true,
	}
}
