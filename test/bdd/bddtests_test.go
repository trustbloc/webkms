/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bdd

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cucumber/godog"

	"github.com/trustbloc/hub-kms/test/bdd/dockerutil"
	"github.com/trustbloc/hub-kms/test/bdd/pkg/common"
	"github.com/trustbloc/hub-kms/test/bdd/pkg/context"
	"github.com/trustbloc/hub-kms/test/bdd/pkg/healthcheck"
	"github.com/trustbloc/hub-kms/test/bdd/pkg/keystore"
	"github.com/trustbloc/hub-kms/test/bdd/pkg/kms"
)

const (
	featuresPath           = "features"
	caCertPath             = "fixtures/keys/tls/ec-cacert.pem"
	kmsRestComposeFilePath = "./fixtures/kms-rest"
	couchDBComposeFilePath = "./fixtures/couchdb"
)

// Feature of the system under test.
type feature interface {
	// SetContext is called before every scenario is run with a fresh new context
	SetContext(*context.BDDContext)
	// RegisterSteps is invoked once to register the steps on the suite
	RegisterSteps(ctx *godog.ScenarioContext)
}

func TestMain(m *testing.M) {
	// default is to run all tests with tag @all
	tags := "all"

	if os.Getenv("TAGS") != "" {
		tags = os.Getenv("TAGS")
	}

	flag.Parse()

	format := "progress"
	if getCmdArg("test.v") == "true" {
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

func runBDDTests(tags, format string) int {
	return godog.TestSuite{
		Name:                 "hub-kms test suite",
		TestSuiteInitializer: initializeTestSuite,
		ScenarioInitializer:  initializeScenario,
		Options:              buildOptions(tags, format),
	}.Run()
}

func initializeTestSuite(ctx *godog.TestSuiteContext) {
	composeFiles := []string{couchDBComposeFilePath, kmsRestComposeFilePath}

	var composition []*dockerutil.Composition

	ctx.BeforeSuite(func() {
		if os.Getenv("DISABLE_COMPOSITION") == "true" {
			return
		}

		// need a unique name, but docker does not allow '-' in names
		composeProjectName := strings.ReplaceAll(generateUUID(), "-", "")

		for _, v := range composeFiles {
			newComposition, err := dockerutil.NewComposition(composeProjectName, "docker-compose.yml", v)
			if err != nil {
				panic(fmt.Sprintf("Error composing system in BDD context: %s", err))
			}

			composition = append(composition, newComposition)
		}

		fmt.Println("docker-compose up ... waiting for containers to start ...")

		testSleep := 3
		if os.Getenv("TEST_SLEEP") != "" {
			s, err := strconv.Atoi(os.Getenv("TEST_SLEEP"))
			if err != nil {
				panic(fmt.Sprintf("Invalid value found in 'TEST_SLEEP': %s", err))
			}

			testSleep = s
		}

		fmt.Printf("*** testSleep=%d\n\n", testSleep)
		time.Sleep(time.Second * time.Duration(testSleep))
	})

	ctx.AfterSuite(func() {
		for _, c := range composition {
			if c != nil {
				if err := c.GenerateLogs(c.Dir, "docker-compose.log"); err != nil {
					panic(err)
				}

				if _, err := c.Decompose(c.Dir); err != nil {
					panic(err)
				}
			}
		}
	})
}

func initializeScenario(ctx *godog.ScenarioContext) {
	features := features()

	for _, f := range features {
		f.RegisterSteps(ctx)
	}

	ctx.BeforeScenario(func(sc *godog.Scenario) {
		bddContext, err := context.NewBDDContext(caCertPath)
		if err != nil {
			panic(fmt.Sprintf("Error returned from NewBDDContext: %s", err))
		}

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
		Randomize:     time.Now().UTC().UnixNano(), // randomize scenario execution order
		Strict:        true,
		StopOnFailure: true,
	}
}

func getCmdArg(argName string) string {
	cmdTags := flag.CommandLine.Lookup(argName)
	if cmdTags != nil && cmdTags.Value != nil && cmdTags.Value.String() != "" {
		return cmdTags.Value.String()
	}

	return ""
}

// generateUUID returns a UUID based on RFC 4122.
func generateUUID() string {
	id := dockerutil.GenerateBytesUUID()

	return fmt.Sprintf("%x-%x-%x-%x-%x", id[0:4], id[4:6], id[6:8], id[8:10], id[10:])
}

func features() []feature {
	return []feature{
		common.NewSteps(),
		healthcheck.NewSteps(),
		keystore.NewSteps(),
		kms.NewSteps(),
	}
}
