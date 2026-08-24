// SPDX-License-Identifier: Apache-2.0

package output

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/giterlizzi/secdb-cli/internal/audit"
)

func TestWriteSARIF_Empty(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, []audit.AdvisoryResult{}, "bom.json"); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}

	var out struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name string `json:"name"`
				} `json:"driver"`
			} `json:"tool"`
			Results []interface{} `json:"results"`
		} `json:"runs"`
	}

	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}

	if out.Version != "2.1.0" {
		t.Errorf("version = %q, want %q", out.Version, "2.1.0")
	}
	if len(out.Runs) != 1 {
		t.Fatalf("expected exactly 1 run, got %d", len(out.Runs))
	}
	if out.Runs[0].Tool.Driver.Name != "secdb-cli" {
		t.Errorf("driver name = %q, want %q", out.Runs[0].Tool.Driver.Name, "secdb-cli")
	}
	if len(out.Runs[0].Results) != 0 {
		t.Errorf("expected no results for no advisories, got %d", len(out.Runs[0].Results))
	}
}

func TestWriteSARIF_OneResultPerPackage(t *testing.T) {
	advisories := []audit.AdvisoryResult{
		{
			ID:        "GHSA-multi",
			Title:     "affects multiple packages",
			Severity:  "medium",
			CVSSScore: 5.5,
			Packages:  []string{"pkg:npm/a@1.0.0", "pkg:npm/b@1.0.0", "pkg:npm/a@1.0.0"},
		},
	}

	var buf bytes.Buffer
	if err := WriteSARIF(&buf, advisories, "bom.json"); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}

	var out struct {
		Runs []struct {
			Results []struct {
				RuleID string `json:"ruleId"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}

	// One result per (advisory, package) entry, including the duplicate "a" package.
	want := []string{
		"GHSA-multi-pkg:npm/a@1.0.0",
		"GHSA-multi-pkg:npm/b@1.0.0",
		"GHSA-multi-pkg:npm/a@1.0.0",
	}
	got := make([]string, 0, len(out.Runs[0].Results))
	for _, r := range out.Runs[0].Results {
		got = append(got, r.RuleID)
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("result ruleIds = %v, want %v", got, want)
	}
}

func TestSeverityToSARIFLevel(t *testing.T) {
	cases := []struct {
		severity string
		want     string
	}{
		{"critical", "error"},
		{"high", "error"},
		{"medium", "warning"},
		{"moderate", "warning"},
		{"low", "note"},
		{"info", "note"},
		{"unknown", "note"},
		{"", "note"},
	}

	for _, c := range cases {
		t.Run(c.severity, func(t *testing.T) {
			got := severityToSARIFLevel(audit.AdvisoryResult{Severity: c.severity})
			if got != c.want {
				t.Errorf("severityToSARIFLevel(%q) = %q, want %q", c.severity, got, c.want)
			}
		})
	}
}

func TestSeverityToScore(t *testing.T) {
	cases := []struct {
		name string
		adv  audit.AdvisoryResult
		want string
	}{
		{"cvss score wins over severity", audit.AdvisoryResult{Severity: "low", CVSSScore: 8.7}, "8.7"},
		{"critical fallback", audit.AdvisoryResult{Severity: "critical"}, "9.5"},
		{"high fallback", audit.AdvisoryResult{Severity: "high"}, "7.5"},
		{"medium fallback", audit.AdvisoryResult{Severity: "medium"}, "5.0"},
		{"moderate fallback", audit.AdvisoryResult{Severity: "moderate"}, "5.0"},
		{"low fallback", audit.AdvisoryResult{Severity: "low"}, "2.0"},
		{"unknown fallback", audit.AdvisoryResult{Severity: "unknown"}, "0.0"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := severityToScore(c.adv)
			if got != c.want {
				t.Errorf("severityToScore(%+v) = %q, want %q", c.adv, got, c.want)
			}
		})
	}
}

func TestBuildTags(t *testing.T) {
	adv := audit.AdvisoryResult{
		CWEs: []string{"CWE-502", "cwe-79"},
		CVEs: []string{"CVE-2021-44228"},
	}

	want := []string{"security", "vulnerability", "external/cwe/cwe-502", "external/cwe/cwe-79", "CVE-2021-44228"}
	got := buildTags(adv)

	if !reflect.DeepEqual(got, want) {
		t.Errorf("buildTags(%+v) = %v, want %v", adv, got, want)
	}
}

func TestBuildFullDescription(t *testing.T) {
	cases := []struct {
		name string
		adv  audit.AdvisoryResult
		want string
	}{
		{"both", audit.AdvisoryResult{Summary: "sum", Description: "desc"}, "sum\n\ndesc"},
		{"description only", audit.AdvisoryResult{Description: "desc"}, "desc"},
		{"summary only", audit.AdvisoryResult{Summary: "sum"}, "sum"},
		{"neither", audit.AdvisoryResult{}, ""},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := buildFullDescription(c.adv)
			if got != c.want {
				t.Errorf("buildFullDescription(%+v) = %q, want %q", c.adv, got, c.want)
			}
		})
	}
}

func TestWriteSARIF_Suppressions(t *testing.T) {
	advisories := []audit.AdvisoryResult{
		{
			ID:       "GHSA-active",
			Title:    "active finding",
			Severity: "high",
			Packages: []string{"pkg:npm/foo@1.0.0"},
		},
		{
			ID:           "GHSA-ignored",
			Title:        "ignored finding",
			Severity:     "critical",
			Packages:     []string{"pkg:npm/bar@1.0.0"},
			Ignored:      true,
			IgnoreReason: "accepted risk, ticket JIRA-123",
		},
	}

	var buf bytes.Buffer
	if err := WriteSARIF(&buf, advisories, "bom.json"); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}

	var out struct {
		Runs []struct {
			Results []struct {
				RuleID       string `json:"ruleId"`
				Suppressions []struct {
					Kind          string `json:"kind"`
					Status        string `json:"status"`
					Justification string `json:"justification"`
				} `json:"suppressions"`
			} `json:"results"`
		} `json:"runs"`
	}

	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}

	if len(out.Runs) != 1 || len(out.Runs[0].Results) != 2 {
		t.Fatalf("expected 1 run with 2 results, got %+v", out)
	}

	results := out.Runs[0].Results

	active := results[0]
	if active.RuleID != "GHSA-active-pkg:npm/foo@1.0.0" {
		t.Fatalf("unexpected first result: %+v", active)
	}
	if len(active.Suppressions) != 0 {
		t.Errorf("active (non-ignored) finding must not carry a suppression, got %+v", active.Suppressions)
	}

	ignored := results[1]
	if ignored.RuleID != "GHSA-ignored-pkg:npm/bar@1.0.0" {
		t.Fatalf("unexpected second result: %+v", ignored)
	}
	if len(ignored.Suppressions) != 1 {
		t.Fatalf("ignored finding must carry exactly one suppression, got %+v", ignored.Suppressions)
	}

	s := ignored.Suppressions[0]
	if s.Kind != "external" {
		t.Errorf("suppression kind = %q, want %q", s.Kind, "external")
	}
	if s.Status != "accepted" {
		t.Errorf("suppression status = %q, want %q", s.Status, "accepted")
	}
	if s.Justification != "accepted risk, ticket JIRA-123" {
		t.Errorf("suppression justification = %q, want the ignore reason", s.Justification)
	}
}

func TestWriteSARIF_SuppressionDefaultJustification(t *testing.T) {
	advisories := []audit.AdvisoryResult{
		{
			ID:       "GHSA-ignored-noreason",
			Title:    "ignored, no reason given",
			Severity: "low",
			Packages: []string{"pkg:npm/baz@1.0.0"},
			Ignored:  true,
		},
	}

	var buf bytes.Buffer
	if err := WriteSARIF(&buf, advisories, ""); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}

	if !bytes.Contains(buf.Bytes(), []byte(`"justification": "Ignored via .secdbignore"`)) {
		t.Errorf("expected a default justification when IgnoreReason is empty, got: %s", buf.String())
	}
}
