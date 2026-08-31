// SPDX-License-Identifier: Apache-2.0

// Package client is a thin HTTP transport for the ZEN SecDB API. This file
// holds the transport itself (the Client, its constructor and request
// plumbing); the request/response models live in models.go and each endpoint
// has its own file (cve.go, audit.go, ssvc.go).
package client

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/giterlizzi/secdb-cli/internal/meta"
)

const defaultBaseURL = "https://secdb.nttzen.cloud"

var userAgent = fmt.Sprintf("secdb-cli/%s (+https://github.com/giterlizzi/secdb-cli)", meta.Version)

type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

func NewClient(apiKey string) *Client {
	return &Client{
		baseURL:    defaultBaseURL,
		apiKey:     apiKey,
		httpClient: &http.Client{Timeout: 60 * time.Second},
	}
}

func (c *Client) WithBaseURL(url string) *Client {
	c.baseURL = strings.TrimRight(url, "/")
	return c
}

// BaseURL returns the configured base URL (no trailing slash). The ZEN SecDB
// web GUI shares this host, so callers build permalinks like
// BaseURL()+"/cve/detail/CVE-..." that follow a custom --base-url.
func (c *Client) BaseURL() string {
	return c.baseURL
}

func (c *Client) request(req *http.Request) ([]byte, error) {

	req.Header = http.Header{
		"Content-Type": {"application/json"},
		"User-Agent":   {userAgent},
	}

	if c.apiKey != "" {
		req.Header.Set("X-API-KEY", c.apiKey)
	}

	slog.Debug("request", "method", req.Method, "url", req.URL)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	slog.Debug("response", "status", resp.Status)
	logRateLimit(resp)

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

// logRateLimit, log the total remaining and used requests from RateLimit-* headers
func logRateLimit(resp *http.Response) {

	remaining := resp.Header.Get("RateLimit-Remaining")
	limit := resp.Header.Get("RateLimit-Limit")
	used := resp.Header.Get("RateLimit-Used")
	reset := resp.Header.Get("RateLimit-Reset")

	if limit == "" && remaining == "" {
		return
	}

	slog.Debug("rate limit",
		"used", used,
		"remaining", remaining,
		"limit", limit,
		"reset_seconds", reset,
	)
}
