// SPDX-License-Identifier: Apache-2.0

// This file defines where the inventory commands run (Target: the local
// machine, an SSH host, a Docker image or container) and the checks on it.

package inventory

import (
	"fmt"
	"strings"
)

// Target describes where commands are executed. The zero value (no Host, Image
// or Container) runs commands on the local machine.
type Target struct {
	Host         string // SSH host, loopback included; empty means local
	Port         string // SSH port (default 22)
	User         string // SSH user
	IdentityFile string // SSH identity (private key) file
	ConfigFile   string // SSH config file; when set, StrictHostKeyChecking is left to it
	Image        string // Docker image to run the command in
	Container    string // Docker container to exec the command in
	Sudo         bool   // prefix package/host commands with "sudo -n"
	Verbose      bool   // pass -vvv to ssh
}

// Describe returns a short, human-readable description of where the audit runs,
// for the report metadata header.
func (t Target) Describe() string {
	switch {
	case t.Image != "":
		return "Docker image " + t.Image
	case t.Container != "":
		return "Docker container " + t.Container
	case t.isRemote():
		host := t.Host
		if t.User != "" {
			host = t.User + " @ " + host
		}
		if t.Port != "" {
			host = host + ":" + t.Port
		}
		return host
	default:
		return "local"
	}
}

// isLocal reports whether commands run directly on this machine (no Docker, no
// SSH).
func (t Target) isLocal() bool {
	return t.Image == "" && t.Container == "" && !t.isRemote()
}

// isRemote reports whether the target is a remote host reached over SSH.
func (t Target) isRemote() bool {
	return t.Host != ""
}

// isDocker reports whether commands run in a Docker image or container.
func (t Target) isDocker() bool {
	return t.Image != "" || t.Container != ""
}

// checkLocalSupported rejects a local audit on a non-Linux host. A local audit
// reads Linux-specific files and package managers, so it only makes sense on
// Linux; a remote (SSH) or Docker target may be Linux regardless of the OS this
// CLI runs on, so the check is limited to local execution.
func checkLocalSupported(t Target, goos string) error {
	if t.isLocal() && goos != "linux" {
		return fmt.Errorf("local audit is only supported on Linux (this is %s); use a remote host or Docker target to audit a Linux system from %s", goos, goos)
	}
	return nil
}

// checkDockerName rejects a Docker image or container name starting with "-".
// The name is a discrete argv element, so it can't inject shell commands, but
// docker would still parse it as one of its own options (e.g.
// --image=--privileged or --image=--volume=/:/host); no valid image or
// container name starts with a dash.
func checkDockerName(t Target) error {
	if strings.HasPrefix(t.Image, "-") {
		return fmt.Errorf("invalid --image %q: a Docker name can't start with \"-\"", t.Image)
	}
	if strings.HasPrefix(t.Container, "-") {
		return fmt.Errorf("invalid --container %q: a Docker name can't start with \"-\"", t.Container)
	}
	return nil
}
