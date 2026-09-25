// SPDX-License-Identifier: Apache-2.0

package client

import (
	"encoding/json"
	"fmt"
	"strings"
)

// GetCVE fetches a CVE by ID, expanding the given related resources.
func (c *Client) GetCVE(id string, expand ...string) (map[string]interface{}, error) {
	path := "/api/v1/feed/cve/" + id
	if len(expand) > 0 {
		path += "?expand=" + strings.Join(expand, ",")
	}

	res, err := c.get(path)
	if err != nil {
		return nil, fmt.Errorf("failed to get CVE: %w", err)
	}

	var data map[string]interface{}
	if err := json.Unmarshal(res.Body, &data); err != nil {
		return nil, fmt.Errorf("parse JSON: %w", err)
	}

	return data, nil
}
