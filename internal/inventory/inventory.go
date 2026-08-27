// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"fmt"
	"log/slog"
	"runtime"
	"strings"
)

// SystemInfo is the minimal system identity needed to audit a Linux host
// against ZEN SecDB: the normalized OS/version, architecture, and the raw
// installed-package lines (as emitted by the native package manager).
type SystemInfo struct {
	OS       string
	Version  string
	Arch     string
	Packages []string
}

// OSRelease holds the /etc/os-release fields used to identify the distribution.
type OSRelease struct {
	ID              string
	VersionID       string
	Version         string
	VersionCodename string
	PrettyName      string
}

// Collect gathers OS identity, architecture and the installed-package list from
// the target, applying the SecDB OS/version normalization. It runs only fixed,
// read-only commands. It errors if the OS can't be identified or isn't
// supported for package auditing.
func Collect(t Target) (*SystemInfo, error) {
	if err := checkLocalSupported(t, runtime.GOOS); err != nil {
		return nil, err
	}

	osr, err := collectOSRelease(t)
	if err != nil {
		return nil, err
	}
	if osr.ID == "" {
		return nil, fmt.Errorf("could not identify the operating system (no readable /etc/os-release)")
	}

	arch := ""
	if r, err := t.run("uname -m"); err == nil {
		arch = strings.TrimSpace(r.Stdout)
	}

	pkgs, err := collectPackages(t, osr.ID)
	if err != nil {
		return nil, err
	}
	if len(pkgs) == 0 {
		return nil, fmt.Errorf("no installed packages were collected for %q", osr.ID)
	}

	os, version := normalizeOSVersion(osr)

	slog.Info("collected system info", "os", os, "version", version, "arch", arch, "packages", len(pkgs))

	return &SystemInfo{OS: os, Version: version, Arch: arch, Packages: pkgs}, nil
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

func collectOSRelease(t Target) (OSRelease, error) {
	r, err := t.run("cat /etc/os-release")
	if err != nil {
		return OSRelease{}, fmt.Errorf("read /etc/os-release command failed: %s", strings.TrimSpace(r.Stderr))
	}
	return parseOSRelease(r.Stdout), nil
}

func parseOSRelease(content string) OSRelease {
	o := OSRelease{}

	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		value = strings.Trim(value, `"'`)

		switch key {
		case "ID":
			o.ID = value
		case "VERSION_ID":
			o.VersionID = value
		case "VERSION":
			o.Version = value
		case "VERSION_CODENAME":
			o.VersionCodename = value
		case "PRETTY_NAME":
			o.PrettyName = value
		}
	}

	return o
}

// installedPackagesCommand returns the read-only command that lists installed packages
// for a distribution ID, and whether the distribution is supported.
func installedPackagesCommand(osID string) (string, bool) {
	switch osID {
	case "debian", "ubuntu":
		return `dpkg-query -W -f='${Package} ${Version} ${Architecture}\n'`, true
	case "centos", "redhat", "rhel", "almalinux", "oraclelinux", "ol", "rockylinux", "amazonlinux", "amzn", "cblmariner", "fedora", "sles", "opensuse-leap":
		return `rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n'`, true
	case "alpine":
		return "apk list --installed", true
	case "slackware":
		return "ls -1 /var/log/packages/", true
	default:
		return "", false
	}
}

func collectPackages(t Target, osID string) ([]string, error) {
	cmd, ok := installedPackagesCommand(osID)
	if !ok {
		return nil, fmt.Errorf("package auditing is not supported for OS %q", osID)
	}

	r, err := t.runSudo(cmd)
	if err != nil {
		return nil, fmt.Errorf("list installed packages command failed: %s", strings.TrimSpace(r.Stderr))
	}

	lines := []string{}
	for _, line := range strings.Split(strings.TrimSpace(r.Stdout), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines, nil
}

// normalizeOSVersion maps os-release fields to the OS/version identifiers the
// ZEN SecDB /api/v1/audit/linux endpoint expects.
func normalizeOSVersion(osr OSRelease) (os, version string) {
	os = osr.ID
	version = osr.VersionID

	switch osr.ID {
	case "ol":
		os = "oraclelinux"
		version = fmt.Sprintf("%s-%s", os, osr.VersionID)
	case "ubuntu", "debian":
		if osr.VersionCodename != "" {
			version = osr.VersionCodename
		} else {
			version = osr.Version
		}
	case "alpine":
		if strings.Contains(osr.PrettyName, "edge") {
			version = "alpine-edge"
		} else if parts := strings.Split(osr.VersionID, "."); len(parts) >= 2 {
			version = fmt.Sprintf("alpine-%s.%s", parts[0], parts[1])
		}
	case "slackware":
		if strings.Contains(osr.PrettyName, "current") {
			version = "current"
		}
	}

	return os, version
}
