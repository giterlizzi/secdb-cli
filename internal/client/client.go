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
	"net/url"
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

type ClientResponse struct {
	Body   []byte
	Header *http.Header
}

func NewClient() *Client {
	return &Client{
		baseURL:    defaultBaseURL,
		httpClient: &http.Client{Timeout: 120 * time.Second},
	}
}

func (c *Client) WithApiKey(apiKey string) *Client {
	if apiKey != "" {
		c.apiKey = apiKey
	}
	return c
}

func (c *Client) WithBaseURL(baseURL string) *Client {
	if baseURL != "" {
		if u, err := url.Parse(baseURL); err == nil && u.Scheme != "" && u.Host != "" {
			c.baseURL = strings.TrimRight(baseURL, "/")
		} else {
			slog.Warn("invalid --base-url, falling back to default", "base_url", baseURL, "default", c.baseURL)
		}
	}
	return c
}

// BaseURL returns the configured base URL (no trailing slash). The ZEN SecDB
// web GUI shares this host, so callers build permalinks like
// BaseURL()+"/cve/detail/CVE-..." that follow a custom --base-url.
func (c *Client) BaseURL() string {
	return c.baseURL
}

func (c *Client) request(req *http.Request) (ClientResponse, error) {

	req.Header = http.Header{
		"Content-Type": {"application/json"},
		"User-Agent":   {userAgent},
	}

	if c.apiKey != "" {
		req.Header.Set("X-API-KEY", c.apiKey)
	}

	slog.Debug("request", "method", req.Method, "url", req.URL)

	res, err := c.httpClient.Do(req)
	if err != nil {
		return ClientResponse{}, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = res.Body.Close() }()

	slog.Debug("response", "status", res.Status)
	logRateLimit(&res.Header)

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return ClientResponse{}, fmt.Errorf("read body: %w", err)
	}

	switch res.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return ClientResponse{}, fmt.Errorf("not found")
	case http.StatusUnauthorized:
		return ClientResponse{}, fmt.Errorf("unauthorized")
	case http.StatusTooManyRequests:
		return ClientResponse{}, fmt.Errorf("rate-limit error")
	default:
		return ClientResponse{}, fmt.Errorf("API error (status %d): %s", res.StatusCode, string(body))
	}

	return ClientResponse{
		Body:   body,
		Header: &res.Header,
	}, nil
}

func (c *Client) get(path string) (ClientResponse, error) {
	req, err := http.NewRequest(http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return ClientResponse{}, fmt.Errorf("build request: %w", err)
	}

	return c.request(req)
}

func (c *Client) post(path string, body io.Reader) (ClientResponse, error) {
	req, err := http.NewRequest(http.MethodPost, c.baseURL+path, body)
	if err != nil {
		return ClientResponse{}, fmt.Errorf("build request: %w", err)
	}

	return c.request(req)
}

// logRateLimit, log the total remaining and used requests from RateLimit-* headers
func logRateLimit(h *http.Header) {

	remaining := h.Get("RateLimit-Remaining")
	limit := h.Get("RateLimit-Limit")
	used := h.Get("RateLimit-Used")
	reset := h.Get("RateLimit-Reset")

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
