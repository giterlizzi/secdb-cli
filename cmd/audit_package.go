// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/giterlizzi/secdb-cli/internal/inventory"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/spf13/cobra"
)

var (
	linuxHost         string
	linuxPort         string
	linuxUser         string
	linuxIdentityFile string
	linuxConfigFile   string
	linuxSudo         bool
	linuxOpts         auditOptions
)

var linuxAuditCmd = &cobra.Command{
	Use:   "linux [ssh://user@host:port]",
	Short: "Audit the installed packages of a Linux system against ZEN SecDB",
	Long: heredoc.Doc(`
		Collects the OS identity and the installed-package list of a Linux system
		and audits them against the ZEN SecDB for known vulnerabilities.

		By default the local machine is audited (local auditing is only supported
		on Linux). To audit a remote host over SSH, pass an ssh:// URI as argument
		(e.g. ssh://user@server.example.com:2222) or use --host/--user/--port. The
		URI is a shorthand: the host, user and port it carries override those
		flags, while --identity-file/--ssh-config/--sudo still apply. SSH uses your
		ssh client, so ~/.ssh/config, the SSH agent and known_hosts all apply. To
		audit a Docker image or container, use "secdb audit docker".

		Only fixed, read-only commands are executed on the target: reading
		/etc/os-release, "uname -m", and the distribution's package-list command
		(dpkg-query / rpm / apk / ...).
	`),
	Args: cobra.MaximumNArgs(1),
	Example: heredoc.Doc(`
		Local system:
			secdb audit linux

		Remote host over SSH (URI shorthand):
			secdb audit linux ssh://user@server.example.com:2222

		Remote host over SSH (flags):
			secdb audit linux --host server.example.com --user ops

		CI (fail on high/critical):
			secdb audit linux --fail-on=high
	`),
	RunE: func(cmd *cobra.Command, args []string) error {

		if len(args) > 0 {
			uri := args[0]

			if !strings.Contains(uri, "://") {
				uri = "ssh://" + uri
			}

			u, err := url.Parse(uri)
			if err != nil {
				return fmt.Errorf("invalid SSH URI %q: %w", uri, err)
			}

			if u.Scheme != "ssh" {
				return fmt.Errorf("unknown scheme %q", u.Scheme)
			}

			if u.Hostname() != "" {
				linuxHost = u.Hostname()

				if u.Port() != "" {
					linuxPort = u.Port()
				}

				if u.User.Username() != "" {
					linuxUser = u.User.Username()
				}
			}
		}

		target := inventory.Target{
			Host:         linuxHost,
			Port:         linuxPort,
			User:         linuxUser,
			IdentityFile: linuxIdentityFile,
			ConfigFile:   linuxConfigFile,
			Sudo:         linuxSudo,
		}
		return runPackageAudit(target, &linuxOpts)
	},
}

func init() {
	auditCmd.AddCommand(linuxAuditCmd)

	linuxAuditCmd.Flags().StringVar(&linuxHost, "host", "",
		"Audit a remote host over SSH (default: local machine)")
	linuxAuditCmd.Flags().StringVar(&linuxPort, "port", "",
		"SSH port (default 22)")
	linuxAuditCmd.Flags().StringVar(&linuxUser, "user", "",
		"SSH user")
	linuxAuditCmd.Flags().StringVar(&linuxIdentityFile, "identity-file", "",
		"SSH identity (private key) file")
	linuxAuditCmd.Flags().StringVar(&linuxConfigFile, "ssh-config", "",
		"SSH config file (when set, host-key policy is left to it)")
	linuxAuditCmd.Flags().BoolVar(&linuxSudo, "sudo", false,
		"Prefix package-list commands with 'sudo -n'")

	linuxOpts.addFlags(linuxAuditCmd)
}
