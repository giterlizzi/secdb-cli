// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"fmt"
	"os"
	"slices"
	"time"

	packageurl "github.com/package-url/packageurl-go"
	"gopkg.in/yaml.v3"
)

// IgnorePackage optionally narrows an ignore rule to a specific package.
type IgnorePackage struct {
	Name    string `yaml:"name,omitempty"`
	Version string `yaml:"version,omitempty"`
}

// IgnoreRule is a single rule from the ignore file.
type IgnoreRule struct {
	Vulnerability string         `yaml:"vulnerability,omitempty"`
	Package       *IgnorePackage `yaml:"package,omitempty"`
	Reason        string         `yaml:"reason"`
	Expires       string         `yaml:"expires,omitempty"`
}

// IgnoreFile is the parsed set of ignore rules (default .secdbignore).
type IgnoreFile struct {
	Ignore []IgnoreRule `yaml:"ignore"`
}

// LoadIgnoreFile reads the YAML ignore file at path, returning an empty (non-nil)
// IgnoreFile when it does not exist.
func LoadIgnoreFile(path string) (*IgnoreFile, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &IgnoreFile{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	var f IgnoreFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	// Reject a malformed expires date up front: silently skipping the rule
	// would re-enable the finding (and --fail-on) without the operator noticing.
	for i, rule := range f.Ignore {
		if rule.Expires == "" {
			continue
		}
		if _, err := time.Parse(time.DateOnly, rule.Expires); err != nil {
			return nil, fmt.Errorf("parsing %s: rule %d (%s): invalid expires %q (want YYYY-MM-DD)", path, i+1, rule.Vulnerability, rule.Expires)
		}
	}
	return &f, nil
}

// active reports whether the rule applies at now. A rule without expires
// always does; one with an expires date applies through the end of that day in
// now's location (local time): the date is the calendar day the operator
// wrote, not a UTC instant. A malformed date makes the rule inactive (only
// possible for a rule built by hand, since LoadIgnoreFile rejects it).
func (r IgnoreRule) active(now time.Time) bool {
	if r.Expires == "" {
		return true
	}
	exp, err := time.ParseInLocation(time.DateOnly, r.Expires, now.Location())
	if err != nil {
		return false
	}
	return now.Before(exp.AddDate(0, 0, 1))
}

// IsIgnored reports whether an advisory (by ID or one of its CVEs, optionally
// scoped to a package) matches a rule, returning the rule's reason.
func (f *IgnoreFile) IsIgnored(advisoryID string, cves []string, purl string) (bool, string) {
	if f == nil {
		return false, ""
	}

	now := time.Now()

	for _, rule := range f.Ignore {
		if !rule.active(now) {
			continue
		}

		matched := rule.Vulnerability != "" && (rule.Vulnerability == advisoryID || slices.Contains(cves, rule.Vulnerability))

		if matched && rule.Package != nil {
			parsed, _ := packageurl.FromString(purl)

			if rule.Package.Name != "" && parsed.Name != rule.Package.Name {
				matched = false
			}

			if matched && rule.Package.Version != "" && parsed.Version != rule.Package.Version {
				matched = false
			}
		}

		if matched {
			return true, rule.Reason
		}
	}
	return false, ""
}
