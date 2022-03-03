/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package cli

import (
	"bytes"
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"github.com/cucumber/godog"

	"github.com/trustbloc/kms/test/bdd/pkg/context"
)

// Steps defines steps context for the KMS cli operations.
type Steps struct {
	cliValue string
}

// NewCLISteps returns new agent from client SDK.
func NewCLISteps() *Steps {
	return &Steps{}
}

// SetContext sets a fresh context for every scenario.
func (e *Steps) SetContext(ctx *context.BDDContext) {
}

// RegisterSteps registers agent steps.
func (e *Steps) RegisterSteps(s *godog.ScenarioContext) {
	s.Step(`^KMS keystore is created through cli$`, e.createKeystore)
	s.Step(`^KMS key is created through cli$`, e.createKey)

	s.Step(`^check cli created valid keystore`, e.checkCreatedKeystore)
	s.Step(`^check cli created valid key$`, e.checkCreatedKey)
}

func (e *Steps) createKeystore() error {
	args := []string{
		"keystore", "create",
		"--controller", "did:example:123456",
		"--url", "https://localhost:8078",
		"--tls-cacerts", "fixtures/keys/tls/ec-cacert.pem",
	}

	value, err := execCMD(args...)
	if err != nil {
		return err
	}

	e.cliValue = value

	return nil
}

func (e *Steps) createKey() error {
	err := e.checkCreatedKeystore()
	if err != nil {
		return err
	}

	keystoreID := strings.Split(e.cliValue, "=")[1]

	args := []string{
		"key", "create",
		"--type", "ED25519",
		"--keystore", keystoreID,
		"--url", "https://localhost:8078",
		"--tls-cacerts", "fixtures/keys/tls/ec-cacert.pem",
	}

	value, err := execCMD(args...)
	if err != nil {
		return err
	}

	e.cliValue = value

	return nil
}

func (e *Steps) checkCreatedKeystore() error {
	parts := strings.Split(e.cliValue, "=")

	if len(parts) != 2 || parts[0] != "keystore" || len(parts[1]) == 0 { //nolint:gocritic
		return fmt.Errorf("invalid response, should be in form keystore={keystoreid}")
	}

	return nil
}

func (e *Steps) checkCreatedKey() error {
	parts := strings.Split(e.cliValue, "=")

	if len(parts) < 2 || parts[0] != "keyURL" || len(parts[1]) == 0 { //nolint:gocritic
		return fmt.Errorf("invalid response, should be in form keyURL={url}")
	}

	return nil
}

func execCMD(args ...string) (string, error) {
	cmd := exec.Command(fmt.Sprintf("../../.build/extract/kms-cli-%s-amd64", runtime.GOOS), args...) // nolint: gosec

	var out bytes.Buffer

	var stderr bytes.Buffer

	cmd.Stdout = &out
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf(fmt.Sprint(err) + ": " + stderr.String())
	}

	return out.String(), nil
}
