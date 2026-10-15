// SPDX-License-Identifier: Apache-2.0

// This file runs a command on a Target: through the local shell, the ssh
// client or docker, always as a discrete argv, never through a host shell
// string built from user input.

package inventory

import (
	"bytes"
	"errors"
	"log/slog"
	"os/exec"
	"runtime"
	"strings"
)

// Result is the outcome of running one command.
type Result struct {
	Command    string
	Stdout     string
	Stderr     string
	ExitStatus int
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
//
// An image runs with --entrypoint /bin/sh: without it, an image ENTRYPOINT
// would run with our command as its arguments, failing on a binary entrypoint
// and executing the image's own code. The container also gets no network, since
// listing packages needs none.
func dockerArgv(t Target, cmdStr string) []string {
	switch {
	case t.Image != "":
		return []string{"run", "--rm", "--network", "none", "--entrypoint", "/bin/sh", t.Image, "-c", cmdStr}
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

	// name is always docker, /bin/sh or the ssh client (see the callers), never
	// user input; args are discrete argv elements, never shell-interpolated.
	cmd := exec.Command(name, args...) //nolint:gosec // G204: fixed program set, see above
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
	if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
		return exitErr.ExitCode()
	}
	return -1
}
