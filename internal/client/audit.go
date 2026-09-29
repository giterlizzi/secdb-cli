// SPDX-License-Identifier: Apache-2.0

package client

import "fmt"

// PURLAudit audits the given PURLs, returning one result per package.
func (c *Client) PURLAudit(purls []string) ([]AuditItem, error) {
	data, err := postJSON[[]AuditItem](c, "/api/v1/audit/purl", purlAuditRequest{Purls: purls})
	if err != nil {
		return nil, fmt.Errorf("failed to audit PURLs: %w", err)
	}
	return data, nil
}

// LinuxAudit audits the installed packages of a Linux OS/version/arch.
func (c *Client) LinuxAudit(osName, version, arch string, packages []string) ([]AuditItem, error) {
	data, err := postJSON[[]AuditItem](c, "/api/v1/audit/linux", linuxAuditRequest{
		OS:       osName,
		Version:  version,
		Arch:     arch,
		Packages: packages,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to audit Linux packages: %w", err)
	}
	return data, nil
}
