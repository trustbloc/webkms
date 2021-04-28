/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dockerutil

import (
	"fmt"
	"os/exec"
	"strings"
)

// DockerHelper helper for docker specific functions.
type DockerHelper interface {
	RemoveContainersWithNamePrefix(namePrefix string) error
}

// NewDockerCmdlineHelper returns a new command line DockerHelper instance.
func NewDockerCmdlineHelper() DockerHelper {
	return &dockerCmdlineHelper{}
}

type dockerCmdlineHelper struct{}

func splitDockerCommandResults(cmdOutput string) (linesToReturn []string) {
	lines := strings.Split(cmdOutput, "\n")
	for _, line := range lines {
		if len(line) > 0 {
			linesToReturn = append(linesToReturn, line)
		}
	}

	return linesToReturn
}

func (d *dockerCmdlineHelper) issueDockerCommand(cmdArgs []string) (string, error) {
	var cmdOut []byte

	var err error

	cmd := exec.Command("docker", cmdArgs...) //nolint:gosec // subprocess launched with variable
	cmdOut, err = cmd.CombinedOutput()

	return string(cmdOut), err
}

func (d *dockerCmdlineHelper) getContainerIDsWithNamePrefix(namePrefix string) ([]string, error) {
	cmdOutput, err := d.issueDockerCommand([]string{"ps", "--filter", fmt.Sprintf("name=%s", namePrefix), "-qa"})
	if err != nil {
		return nil, fmt.Errorf("error getting containers with name prefix '%s': %w",
			namePrefix, err)
	}

	containerIDs := splitDockerCommandResults(cmdOutput)

	return containerIDs, err
}

func (d *dockerCmdlineHelper) RemoveContainersWithNamePrefix(namePrefix string) error {
	containers, err := d.getContainerIDsWithNamePrefix(namePrefix)
	if err != nil {
		return fmt.Errorf("error removing containers with name prefix (%s): %w", namePrefix, err)
	}

	for _, id := range containers {
		fmt.Printf("container: %s", id)

		_, err = d.issueDockerCommand([]string{"rm", "-f", id})
		if err != nil {
			return fmt.Errorf("failed to issue docker command: %w", err)
		}
	}

	return nil
}
