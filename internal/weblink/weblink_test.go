// SPDX-License-Identifier: Apache-2.0

package weblink

import "testing"

func TestLinks(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{"cve", CVE("https://secdb.example.com", "CVE-2021-44228"), "https://secdb.example.com/cve/detail/CVE-2021-44228"},
		{"cwe", CWE("https://secdb.example.com", "CWE-79"), "https://secdb.example.com/cwe/detail/CWE-79"},
		{"advisory", Advisory("https://secdb.example.com", "GHSA-jfh8-c2jp-5v3q"), "https://secdb.example.com/security-advisory/detail/GHSA-jfh8-c2jp-5v3q"},
		{"path prefix and trailing slash", CVE("https://gateway.example.com/secdb/", "CVE-2021-44228"), "https://gateway.example.com/secdb/cve/detail/CVE-2021-44228"},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("%s: got %q, want %q", tt.name, tt.got, tt.want)
		}
	}
}
