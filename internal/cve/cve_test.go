// SPDX-License-Identifier: Apache-2.0

package cve

import (
	"testing"
)

func TestIsValidCVE(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"CVE-2021-44228", true},
		{"CVE-1999-0001", true},
		{"CVE-2023-12345678", true},
		{"cve-2021-44228", true},
		{"Cve-2021-44228", true},
		{"CVE-2021-123", false},
		{"CVE-21-44228", false},
		{"CVE-2021-", false},
		{"CVE-2021", false},
		{"INVALID", false},
		{"", false},
		{"CVE-2021-44228-extra", false},
		{"CVE--44228", false},
		{"xCVE-2021-44228x", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := IsValidCVE(tt.input)
			if got != tt.want {
				t.Errorf("IsValidCVE(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
