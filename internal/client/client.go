// SPDX-License-Identifier: Apache-2.0

// Package client is a thin HTTP transport for the ZEN SecDB API. This file
// holds the transport itself (the Client, its constructor and request
// plumbing); the request/response models live in models.go and each endpoint
// has its own file (cve.go, audit.go, ssvc.go).
package client

import (
	"bytes"
	"encoding/json"
	"errors"
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

// Client is an HTTP client for the ZEN SecDB API.
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// Response holds a decoded API response.
type Response struct {
	Body   []byte
	Header http.Header
}

// maxErrorBody caps how much of an unexpected response body is quoted in the
// returned error, so e.g. a proxy's HTML error page doesn't flood the terminal.
const maxErrorBody = 512

// NewClient returns a Client with the default base URL and timeout.
func NewClient() *Client {
	return &Client{
		baseURL:    defaultBaseURL,
		httpClient: &http.Client{Timeout: 120 * time.Second},
	}
}

// WithAPIKey sets the API key sent with each request (no-op when empty) and
// returns the client for chaining.
func (c *Client) WithAPIKey(apiKey string) *Client {
	if apiKey != "" {
		c.apiKey = apiKey
	}
	return c
}

// WithBaseURL overrides the API base URL (no-op when empty) and returns the
// client for chaining.
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

func (c *Client) request(req *http.Request) (Response, error) {

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
		return Response{}, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = res.Body.Close() }()

	slog.Debug("response", "status", res.Status)
	logRateLimit(res.Header)

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return Response{}, fmt.Errorf("read body: %w", err)
	}

	switch res.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return Response{}, errors.New("not found")
	case http.StatusUnauthorized:
		return Response{}, errors.New("unauthorized (check SECDB_API_KEY)")
	case http.StatusTooManyRequests:
		if reset := res.Header.Get("RateLimit-Reset"); reset != "" {
			return Response{}, fmt.Errorf("rate limit exceeded (retry in %ss)", reset)
		}
		return Response{}, errors.New("rate limit exceeded")
	default:
		if len(body) > maxErrorBody {
			body = append(body[:maxErrorBody], "..."...)
		}
		return Response{}, fmt.Errorf("API error (status %d): %s", res.StatusCode, body)
	}

	return Response{
		Body:   body,
		Header: res.Header,
	}, nil
}

func (c *Client) get(path string) (Response, error) {
	req, err := http.NewRequest(http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return Response{}, fmt.Errorf("build request: %w", err)
	}

	return c.request(req)
}

func (c *Client) post(path string, body io.Reader) (Response, error) {
	req, err := http.NewRequest(http.MethodPost, c.baseURL+path, body)
	if err != nil {
		return Response{}, fmt.Errorf("build request: %w", err)
	}

	return c.request(req)
}

// getJSON GETs path and decodes the JSON response into T.
func getJSON[T any](c *Client, path string) (T, error) {
	res, err := c.get(path)
	if err != nil {
		var zero T
		return zero, err
	}
	return decodeJSON[T](res)
}

// postJSON marshals in, POSTs it to path and decodes the JSON response into T.
func postJSON[T any](c *Client, path string, in any) (T, error) {
	var zero T
	payload, err := json.Marshal(in)
	if err != nil {
		return zero, fmt.Errorf("marshal request: %w", err)
	}
	res, err := c.post(path, bytes.NewReader(payload))
	if err != nil {
		return zero, err
	}
	return decodeJSON[T](res)
}

func decodeJSON[T any](res Response) (T, error) {
	var out T
	if err := json.Unmarshal(res.Body, &out); err != nil {
		return out, fmt.Errorf("parse JSON: %w", err)
	}
	return out, nil
}

// logRateLimit logs the used/remaining requests from the RateLimit-* headers.
func logRateLimit(h http.Header) {

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
