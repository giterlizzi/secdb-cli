// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"fmt"
	"log/slog"
	"os"
	"slices"
	"time"

	packageurl "github.com/package-url/packageurl-go"
	"gopkg.in/yaml.v3"
)

type IgnorePackage struct {
	Name    string `yaml:"name,omitempty"`
	Version string `yaml:"version,omitempty"`
}

type IgnoreRule struct {
	Vulnerability string         `yaml:"vulnerability,omitempty"`
	Package       *IgnorePackage `yaml:"package,omitempty"`
	Reason        string         `yaml:"reason"`
	Expires       string         `yaml:"expires,omitempty"`
}

type IgnoreFile struct {
	Ignore []IgnoreRule `yaml:"ignore"`
}

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
	return &f, nil
}

func (f *IgnoreFile) IsIgnored(advisoryID string, cves []string, pkg string) (bool, string) {
	now := time.Now()

	for _, rule := range f.Ignore {
		if rule.Expires != "" {
			exp, err := time.Parse("2006-01-02", rule.Expires)
			if err != nil {
				slog.Warn("ignore rule has an invalid expires date, skipping it", "vulnerability", rule.Vulnerability, "expires", rule.Expires, "error", err)
				continue
			}
			// expires is a calendar date, so the rule stays active through the end of that day.
			if now.After(exp.AddDate(0, 0, 1)) {
				continue
			}
		}

		matched := rule.Vulnerability != "" && (rule.Vulnerability == advisoryID || slices.Contains(cves, rule.Vulnerability))

		if matched && rule.Package != nil {
			purl, _ := packageurl.FromString(pkg)

			if rule.Package.Name != "" && !(purl.Name == rule.Package.Name) {
				matched = false
			}

			if matched && rule.Package.Version != "" && !(purl.Version == rule.Package.Version) {
				matched = false
			}
		}

		if matched {
			return true, rule.Reason
		}
	}
	return false, ""
}
