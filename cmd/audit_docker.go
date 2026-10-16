// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"

	"github.com/giterlizzi/secdb-cli/internal/inventory"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/spf13/cobra"
)

// dockerOptions are the flags of "audit docker".
type dockerOptions struct {
	image     string
	container string
	audit     auditOptions
}

var dockerOpts dockerOptions

var dockerAuditCmd = &cobra.Command{
	Use:   "docker",
	Short: "Audit the installed packages of a Docker image or container against ZEN SecDB",
	Long: heredoc.Doc(`
		Collects the OS identity and the installed-package list of a Docker image
		or container and audits them against the ZEN SecDB for known
		vulnerabilities.

		Exactly one of --image or --container must be given:

		  --image      run the package-list command in a fresh, ephemeral container
		               of the image ("docker run --rm", with no network and
		               /bin/sh in place of the image's entrypoint)
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
		target, err := dockerOpts.target()
		if err != nil {
			return err
		}
		return runPackageAudit(target, &dockerOpts.audit)
	},
}

func init() {
	auditCmd.AddCommand(dockerAuditCmd)
	dockerOpts.addFlags(dockerAuditCmd)
}

func (o *dockerOptions) addFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&o.image, "image", "",
		"Audit a local Docker image (run ephemerally)")
	cmd.Flags().StringVar(&o.container, "container", "",
		"Audit a running local Docker container")

	o.audit.addFlags(cmd)
}

// target returns the image or container to audit: exactly one must be given.
func (o *dockerOptions) target() (inventory.Target, error) {
	if (o.image == "") == (o.container == "") {
		return inventory.Target{}, errors.New("provide exactly one of --image or --container")
	}
	return inventory.Target{Image: o.image, Container: o.container}, nil
}
