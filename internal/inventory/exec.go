// SPDX-License-Identifier: Apache-2.0

// Package inventory gathers the OS identity and installed-package list of a
// target system (local, remote over SSH, or a Docker image/container) so it can
// be audited against ZEN SecDB. It executes only a fixed, read-only set of
// enumeration commands (see inventory.go).
package inventory

import (
	"bytes"
	"log/slog"
	"os/exec"
	"runtime"
	"strings"
)

// Target describes where commands are executed. The zero value (no Host, Image
// or Container) runs commands on the local machine.
type Target struct {
	Host         string // remote host; empty, "localhost" or "127.0.0.1" means local
	Port         string // SSH port (default 22)
	User         string // SSH user
	IdentityFile string // SSH identity (private key) file
	ConfigFile   string // SSH config file; when set, StrictHostKeyChecking is left to it
	Image        string // Docker image to run the command in
	Container    string // Docker container to exec the command in
	Sudo         bool   // prefix package/host commands with "sudo -n"
	Verbose      bool   // pass -vvv to ssh
}

// Result is the outcome of running one command.
type Result struct {
	Command    string
	Stdout     string
	Stderr     string
	ExitStatus int
}

// isRemote reports whether the target is a remote host reached over SSH.
func (t Target) isRemote() bool {
	return t.Host != "" && t.Host != "localhost" && t.Host != "127.0.0.1"
}

// isLocal reports whether commands run directly on this machine (no Docker, no
// SSH).
func (t Target) isLocal() bool {
	return t.Image == "" && t.Container == "" && !t.isRemote()
}

// isDocker reports whether commands run using Docker engine
func (t Target) isDocker() bool {
	return t.Image != "" || t.Container != ""
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

// run dispatches a command to the right executor based on the target. Docker
// takes precedence over SSH, which takes precedence over local execution.
//
// cmdStr is always a fixed, read-only command from this package (see
// inventory.go), never built from untrusted input. The Docker image/container
// name (from --image/--container) is passed as a discrete argv element, never
// interpolated into a shell string, so it cannot inject host commands.
func (t Target) run(cmdStr string) (Result, error) {
	switch {
	case t.isDocker():
		return t.runArgv("docker", dockerArgv(t, cmdStr)...)
	case t.isRemote():
		return t.runSSH(cmdStr)
	default:
		return t.runLocal(cmdStr)
	}
}

// dockerArgv builds the argv to run cmdStr inside a Docker image or container.
// The image/container name is a single discrete element, so it is never subject
// to shell interpretation. Returns nil when the target isn't a Docker target.
func dockerArgv(t Target, cmdStr string) []string {
	switch {
	case t.Image != "":
		return []string{"run", "--rm", t.Image, "/bin/sh", "-c", cmdStr}
	case t.Container != "":
		return []string{"exec", t.Container, "/bin/sh", "-c", cmdStr}
	default:
		return nil
	}
}

// runArgv executes a program with explicit arguments, without an intervening
// host shell, so no argument can be interpreted as a shell metacharacter.
func (t Target) runArgv(name string, args ...string) (Result, error) {
	var stdout, stderr bytes.Buffer

	cmd := exec.Command(name, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	slog.Debug("executing command", "name", name, "args", args)

	err := cmd.Run()

	rs := Result{Command: name + " " + strings.Join(args, " ")}
	rs.ExitStatus = exitStatus(err)
	rs.Stdout = stdout.String()
	rs.Stderr = stderr.String()

	slog.Debug("command finished", "exit", rs.ExitStatus, "stderr", strings.TrimSpace(rs.Stderr))

	return rs, err
}

// runSudo optionally prefixes the command with "sudo -n" (non-interactive).
func (t Target) runSudo(cmdStr string) (Result, error) {
	if t.Sudo {
		cmdStr = "sudo -n " + cmdStr
	}
	return t.run(cmdStr)
}

func (t Target) runLocal(cmdStr string) (Result, error) {
	return t.runArgv("/bin/sh", "-c", cmdStr)
}

func (t Target) runSSH(cmdStr string) (Result, error) {
	sshExecutable := "ssh"
	if runtime.GOOS == "windows" {
		sshExecutable = "ssh.exe"
	}
	if path, err := exec.LookPath(sshExecutable); err == nil {
		sshExecutable = path
	}

	var sshArgs []string

	if t.ConfigFile != "" {
		sshArgs = append(sshArgs, "-F", t.ConfigFile)
	} else {
		sshArgs = append(sshArgs,
			"-o", "StrictHostKeyChecking=yes",
			"-o", "LogLevel=quiet",
			"-o", "ConnectionAttempts=3",
			"-o", "ConnectTimeout=10",
		)
	}

	if t.Port != "" {
		sshArgs = append(sshArgs, "-p", t.Port)
	}
	if t.User != "" {
		sshArgs = append(sshArgs, "-l", t.User)
	}
	if t.IdentityFile != "" {
		sshArgs = append(sshArgs, "-i", t.IdentityFile, "-o", "PasswordAuthentication=no")
	}
	if t.Verbose {
		sshArgs = append(sshArgs, "-vvv")
	}

	sshArgs = append(sshArgs, "--", t.Host, cmdStr)

	return t.runArgv(sshExecutable, sshArgs...)
}

func exitStatus(err error) int {
	if err == nil {
		return 0
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode()
	}
	return -1
}
