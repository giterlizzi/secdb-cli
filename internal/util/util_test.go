// SPDX-License-Identifier: Apache-2.0

package util

import (
	"testing"
	"time"

	"github.com/spf13/cobra"
)

func TestExactArgs(t *testing.T) {
	fn := ExactArgs(1, "Specify a CVE identifier")
	cmd := &cobra.Command{}

	if err := fn(cmd, []string{"CVE-2021-44228"}); err != nil {
		t.Errorf("unexpected error with 1 arg: %v", err)
	}

	if err := fn(cmd, []string{}); err == nil {
		t.Error("expected error with 0 args, got nil")
	} else if err.Error() != "Specify a CVE identifier" {
		t.Errorf("unexpected error message: %q", err.Error())
	}

	if err := fn(cmd, []string{"a", "b"}); err == nil {
		t.Error("expected error with 2 args, got nil")
	}
}

func TestTimeAgo(t *testing.T) {
	now := time.Now()

	cases := []struct {
		name string
		t    time.Time
		want string
	}{
		{"now", now, "0 minutes ago"},
		{"1 minute", now.Add(-1 * time.Minute), "1 minutes ago"},
		{"5 min", now.Add(-5 * time.Minute), "5 minutes ago"},
		{"59 min", now.Add(-59 * time.Minute), "59 minutes ago"},
		{"1 hour", now.Add(-60 * time.Minute), "1 hour ago"},
		{"5 hours", now.Add(-5 * time.Hour), "5 hours ago"},
		{"23 hours", now.Add(-23 * time.Hour), "23 hours ago"},
		{"1 day", now.Add(-24 * time.Hour), "1 day ago"},
		{"5 days", now.Add(-5 * 24 * time.Hour), "5 days ago"},
		{"1 week", now.Add(-7 * 24 * time.Hour), "7 days ago"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := TimeAgo(c.t)
			if got != c.want {
				t.Errorf("TimeAgo(%v) = %q, want %q", c.t, got, c.want)
			}
		})
	}
}
