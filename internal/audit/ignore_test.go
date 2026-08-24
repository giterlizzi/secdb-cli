// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"testing"
	"time"
)

func TestIsIgnored_PackageVersionScoping(t *testing.T) {
	f := &IgnoreFile{
		Ignore: []IgnoreRule{
			{
				Vulnerability: "CVE-2024-33333",
				Package:       &IgnorePackage{Name: "some-package", Version: "1.0.0"},
				Reason:        "accepted risk for 1.0.0 only",
			},
		},
	}

	if ignored, _ := f.IsIgnored("CVE-2024-33333", nil, "pkg:npm/some-package@1.0.0"); !ignored {
		t.Errorf("expected pinned version 1.0.0 to be ignored")
	}

	if ignored, _ := f.IsIgnored("CVE-2024-33333", nil, "pkg:npm/some-package@2.0.0"); ignored {
		t.Errorf("rule pinned to version 1.0.0 must not match version 2.0.0")
	}
}

func TestIsIgnored_ExpiresIsInclusiveOfWholeDay(t *testing.T) {
	today := time.Now().Format("2006-01-02")
	yesterday := time.Now().AddDate(0, 0, -1).Format("2006-01-02")

	f := &IgnoreFile{
		Ignore: []IgnoreRule{
			{Vulnerability: "CVE-2024-11111", Reason: "expires today", Expires: today},
			{Vulnerability: "CVE-2024-22222", Reason: "expired yesterday", Expires: yesterday},
		},
	}

	if ignored, _ := f.IsIgnored("CVE-2024-11111", nil, "pkg:npm/foo@1.0.0"); !ignored {
		t.Errorf("a rule expiring today must still be active for the rest of today")
	}

	if ignored, _ := f.IsIgnored("CVE-2024-22222", nil, "pkg:npm/foo@1.0.0"); ignored {
		t.Errorf("a rule that expired yesterday must no longer be active")
	}
}

func TestIsIgnored_InvalidExpiresIsSkipped(t *testing.T) {
	f := &IgnoreFile{
		Ignore: []IgnoreRule{
			{Vulnerability: "CVE-2024-33333", Reason: "bad date", Expires: "not-a-date"},
		},
	}

	if ignored, _ := f.IsIgnored("CVE-2024-33333", nil, "pkg:npm/foo@1.0.0"); ignored {
		t.Errorf("a rule with an unparsable expires date must not be applied")
	}
}
