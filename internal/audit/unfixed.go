// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"log/slog"

	"github.com/giterlizzi/secdb-cli/internal/client"

	packageurl "github.com/package-url/packageurl-go"
)

// IsUnfixed reports whether the advisory has no fix available for the audited
// package (identified by purl). It interprets the remediation status the API
// returns: "none_available" on the advisory package that is the same package
// as purl (same type, namespace and name and, when present, the same "distro"
// qualifier). This is audit domain logic (an interpretation of the data), so it
// lives here rather than in the API client.
func IsUnfixed(purl string, adv client.Advisory) bool {
	audited, err := packageurl.FromString(purl)
	if err != nil {
		return false
	}

	for _, pkg := range adv.Packages {
		if pkg.Status == "affected" && pkg.Remediation == "none_available" && isAuditedPackage(audited, pkg.PURL) {
			slog.Debug("no fix is available", "advisory", adv.ID, "package", purl)
			return true
		}
	}
	return false
}

// isAuditedPackage reports whether an advisory package PURL is the audited
// package: same type, namespace and name, and the same "distro" qualifier when
// the audited PURL has one. An advisory often lists sibling packages (lodash
// and lodash.trim, openssl and edk2), and only the audited package's own
// remediation counts.
func isAuditedPackage(audited packageurl.PackageURL, purl string) bool {
	p, err := packageurl.FromString(purl)
	if err != nil || p.Type != audited.Type || p.Namespace != audited.Namespace || p.Name != audited.Name {
		return false
	}
	distro := distroQualifier(audited)
	return distro == "" || distroQualifier(p) == distro
}

func distroQualifier(purl packageurl.PackageURL) string {
	for _, q := range purl.Qualifiers {
		if q.Key == "distro" {
			return q.Value
		}
	}
	return ""
}
