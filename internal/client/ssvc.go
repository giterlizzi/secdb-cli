// SPDX-License-Identifier: Apache-2.0

package client

import "fmt"

// SSVCBulk calculates SSVC decisions for the given CVEs in one request.
func (c *Client) SSVCBulk(cveIDs []string, missionPrevalence string, publicWellBeingImpact string) ([]SSVCBulkResponse, error) {
	data, err := postJSON[[]SSVCBulkResponse](c, "/api/v1/ssvc/bulk", ssvcBulkRequest{
		CVEs:                  cveIDs,
		MissionPrevalence:     missionPrevalence,
		PublicWellBeingImpact: publicWellBeingImpact,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to execute SSVC bulk request: %w", err)
	}
	return data, nil
}
