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

	auditedPurl, err := packageurl.FromString(purl)
	if err != nil {
		return false
	}

	auditedDistro := distroQualifier(auditedPurl)

	for _, pkg := range adv.Packages {
		if pkg.Status != "affected" {
			continue
		}

		advPurl, err := packageurl.FromString(pkg.PURL)
		if err != nil {
			continue
		}
		// An advisory often lists sibling packages (lodash and lodash.trim, openssl
		// and edk2): only the audited package's own remediation counts.
		if auditedPurl.Type != advPurl.Type || auditedPurl.Namespace != advPurl.Namespace || auditedPurl.Name != advPurl.Name {
			continue
		}

		if auditedDistro != "" && distroQualifier(advPurl) != auditedDistro {
			continue
		}

		if pkg.Remediation == "none_available" {
			slog.Debug("no fix is available", "advisory", adv.ID, "package", purl)
			return true
		}
	}

	return false
}

func distroQualifier(purl packageurl.PackageURL) string {
	for _, q := range purl.Qualifiers {
		if q.Key == "distro" {
			return q.Value
		}
	}
	return ""
}
