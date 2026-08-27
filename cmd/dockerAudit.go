// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"

	"github.com/giterlizzi/secdb-cli/internal/inventory"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/spf13/cobra"
)

var (
	dockerImage      string
	dockerContainer  string
	dockerView       string
	dockerFailOn     string
	dockerIgnoreFile string
)

var dockerAuditCmd = &cobra.Command{
	Use:   "docker",
	Short: "Audit the installed packages of a Docker image or container against ZEN SecDB",
	Long: heredoc.Doc(`
		Collects the OS identity and the installed-package list of a Docker image
		or container and audits them against the ZEN SecDB for known
		vulnerabilities.

		Exactly one of --image or --container must be given:

		  --image      run the package-list command in a fresh, ephemeral container
		               of the image ("docker run --rm")
		  --container  exec the package-list command in a running container

		Only fixed, read-only commands are executed inside the target: reading
		/etc/os-release, "uname -m", and the distribution's package-list command.
		The docker CLI must be available and able to reach the daemon.
	`),
	Example: heredoc.Doc(`
		Docker image (ephemeral):
		  	secdb audit docker --image debian:12

		Running container:
		  	secdb audit docker --container my-running-container

		CI (fail on high/critical):
		  	secdb audit docker --image myapp:latest --fail-on=high
	`),
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if (dockerImage == "") == (dockerContainer == "") {
			return fmt.Errorf("provide exactly one of --image or --container")
		}

		target := inventory.Target{
			Image:     dockerImage,
			Container: dockerContainer,
		}
		return runPackageAudit(target, dockerView, dockerFailOn, dockerIgnoreFile)
	},
}

func init() {
	auditCmd.AddCommand(dockerAuditCmd)

	dockerAuditCmd.Flags().StringVar(&dockerImage, "image", "",
		"Audit a local Docker image (run ephemerally)")
	dockerAuditCmd.Flags().StringVar(&dockerContainer, "container", "",
		"Audit a running local Docker container")

	addPackageAuditFlags(dockerAuditCmd, &dockerView, &dockerFailOn, &dockerIgnoreFile)
}
