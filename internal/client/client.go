// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/giterlizzi/secdb-cli/internal/meta"
)

const defaultBaseURL = "https://secdb.nttzen.cloud/"

var userAgent = fmt.Sprintf("secdb-cli/%s (+https://github.com/giterlizzi/secdb-cli)", meta.Version)

type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

type PURLAuditRequest struct {
	Purls []string `json:"purls"`
}

type SSVCBulkRequest struct {
	CVEs                  []string `json:"cves"`
	MissionPrevalence     string   `json:"mission_prevalence"`
	PublicWellBeingImpact string   `json:"public_well_being_impact"`
}

type SSVCBulkResponse struct {
	CVE struct {
		ID    string `json:"id" yaml:"id"`
		Title string `json:"title" yaml:"title"`
	} `json:"cve" yaml:"cve"`
	SSVC   SSVCResponse `json:"ssvc" yaml:"ssvc"`
	Status string       `json:"status" yaml:"status"`

	VectorString string `json:"vector_string" yaml:"vector_string"`
}

type SSVCResponse struct {
	Exploitation           string `json:"exploitation" yaml:"exploitation"`
	Automatable            string `json:"automatable" yaml:"automatable"`
	TechnicalImpact        string `json:"technical_impact" yaml:"technical_impact"`
	MissionPrevalence      string `json:"mission_prevalence" yaml:"mission_prevalence"`
	PublicWellBeingImpact  string `json:"public_well_being_impact" yaml:"public_well_being_impact"`
	MissionWellBeingImpact string `json:"mission_well_being_impact" yaml:"mission_well_being_impact"`
	Decision               string `json:"decision" yaml:"decision"`
}

func NewClient(apiKey string) *Client {
	return &Client{
		baseURL:    defaultBaseURL,
		apiKey:     apiKey,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *Client) WithBaseURL(url string) *Client {
	c.baseURL = url
	return c
}

func (c *Client) request(req *http.Request) ([]byte, error) {

	req.Header = http.Header{
		"Content-Type": {"application/json"},
		"User-Agent":   {userAgent},
	}

	if c.apiKey != "" {
		req.Header.Set("X-API-KEY", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, fmt.Errorf("not found")
	case http.StatusUnauthorized:
		return nil, fmt.Errorf("unauthorized")
	case http.StatusTooManyRequests:
		return nil, fmt.Errorf("rate-limit error")
	default:
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(body))
	}

	return body, nil
}

func (c *Client) get(path string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	return c.request(req)
}

func (c *Client) post(path string, body io.Reader) ([]byte, error) {
	req, err := http.NewRequest(http.MethodPost, c.baseURL+path, body)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	return c.request(req)
}

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

func (c *Client) PURLAudit(purls []string) ([]map[string]interface{}, error) {
	payload, err := json.Marshal(PURLAuditRequest{Purls: purls})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSON: %w", err)
	}

	body, err := c.post("/api/v1/audit/purl", bytes.NewBuffer(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to audit PURLs: %w", err)
	}

	var data []map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("parse JSON: %w", err)
	}

	return data, nil
}

func (c *Client) SSVCBulk(cveIDs []string, missionPrevalence string, publicWellBeingImpact string) ([]SSVCBulkResponse, error) {
	payload, err := json.Marshal(SSVCBulkRequest{
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
