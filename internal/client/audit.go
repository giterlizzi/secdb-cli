// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"encoding/json"
	"fmt"
)

func (c *Client) PURLAudit(purls []string) ([]AuditItem, error) {
	payload, err := json.Marshal(purlAuditRequest{Purls: purls})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSON: %w", err)
	}

	body, err := c.post("/api/v1/audit/purl", bytes.NewBuffer(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to audit PURLs: %w", err)
	}

	var data []AuditItem
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("parse JSON: %w", err)
	}

	return data, nil
}

func (c *Client) LinuxAudit(osName, version, arch string, packages []string) ([]AuditItem, error) {
	payload, err := json.Marshal(linuxAuditRequest{
		OS:       osName,
		Version:  version,
		Arch:     arch,
		Packages: packages,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSON: %w", err)
	}

	body, err := c.post("/api/v1/audit/linux", bytes.NewBuffer(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to audit Linux packages: %w", err)
	}

	var data []AuditItem
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("parse JSON: %w", err)
	}

	return data, nil
}
