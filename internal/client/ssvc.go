// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"encoding/json"
	"fmt"
)

func (c *Client) SSVCBulk(cveIDs []string, missionPrevalence string, publicWellBeingImpact string) ([]SSVCBulkResponse, error) {
	payload, err := json.Marshal(ssvcBulkRequest{
		CVEs:                  cveIDs,
		MissionPrevalence:     missionPrevalence,
		PublicWellBeingImpact: publicWellBeingImpact,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSON: %w", err)
	}

	body, err := c.post("/api/v1/ssvc/bulk", bytes.NewBuffer(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to execute SSVC bulk request: %w", err)
	}

	var data []SSVCBulkResponse
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("parse JSON: %w", err)
	}

	return data, nil
}
