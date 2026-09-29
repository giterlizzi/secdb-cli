// SPDX-License-Identifier: Apache-2.0

package client

import (
	"fmt"
	"strings"
)

// GetCVE fetches a CVE by ID, expanding the given related resources.
func (c *Client) GetCVE(id string, expand ...string) (map[string]any, error) {
	path := "/api/v1/feed/cve/" + id
	if len(expand) > 0 {
		path += "?expand=" + strings.Join(expand, ",")
	}

	data, err := getJSON[map[string]any](c, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get CVE: %w", err)
	}
	return data, nil
}
