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

// linuxOptions are the flags of "audit linux".
type linuxOptions struct {
	host         string
	port         string
	user         string
	identityFile string
	sshConfig    string
	sudo         bool
	audit        auditOptions
}

var linuxOpts linuxOptions

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
		target, err := linuxOpts.target(args)
		if err != nil {
			return err
		}
		return runPackageAudit(target, &linuxOpts.audit)
	},
}

func init() {
	auditCmd.AddCommand(linuxAuditCmd)
	linuxOpts.addFlags(linuxAuditCmd)
}

func (o *linuxOptions) addFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&o.host, "host", "",
		"Audit a remote host over SSH (default: local machine)")
	cmd.Flags().StringVar(&o.port, "port", "",
		"SSH port (default 22)")
	cmd.Flags().StringVar(&o.user, "user", "",
		"SSH user")
	cmd.Flags().StringVar(&o.identityFile, "identity-file", "",
		"SSH identity (private key) file")
	cmd.Flags().StringVar(&o.sshConfig, "ssh-config", "",
		"SSH config file (when set, host-key policy is left to it)")
	cmd.Flags().BoolVar(&o.sudo, "sudo", false,
		"Prefix package-list commands with 'sudo -n'")

	o.audit.addFlags(cmd)
}

// target returns the system to audit: the local machine, or the SSH host of
// the flags. An ssh://user@host:port argument overrides --host/--user/--port.
// With --debug (or SECDB_DEBUG: global.debug, set by setupLogging) ssh runs
// with -vvv, and its connection log goes to the debug output.
func (o *linuxOptions) target(args []string) (inventory.Target, error) {
	t := inventory.Target{
		Host:         o.host,
		Port:         o.port,
		User:         o.user,
		IdentityFile: o.identityFile,
		ConfigFile:   o.sshConfig,
		Sudo:         o.sudo,
		Verbose:      global.debug,
	}
	if len(args) == 0 {
		return t, nil
	}

	uri := args[0]
	if !strings.Contains(uri, "://") {
		uri = "ssh://" + uri
	}
	u, err := url.Parse(uri)
	if err != nil {
		return t, fmt.Errorf("invalid SSH URI %q: %w", uri, err)
	}
	if u.Scheme != "ssh" {
		return t, fmt.Errorf("unknown scheme %q", u.Scheme)
	}
	if u.Hostname() != "" {
		t.Host = u.Hostname()
		if u.Port() != "" {
			t.Port = u.Port()
		}
		if u.User.Username() != "" {
			t.User = u.User.Username()
		}
	}
	return t, nil
}
