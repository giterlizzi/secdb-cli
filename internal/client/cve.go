// SPDX-License-Identifier: Apache-2.0

package client

import (
	"encoding/json"
	"fmt"
	"strings"
)

func (c *Client) GetCVE(id string, expand ...string) (map[string]interface{}, error) {
	path := fmt.Sprintf("/api/v1/feed/cve/%s", id)
	if len(expand) > 0 {
		path += "?expand=" + strings.Join(expand, ",")
	}

	body, err := c.get(path)
	if err != nil {
		return nil, fmt.Errorf("failed to get CVE: %w", err)
	}

	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("parse JSON: %w", err)
	}

	return data, nil
}
