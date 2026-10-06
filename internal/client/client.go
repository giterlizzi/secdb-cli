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
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/giterlizzi/secdb-cli/internal/meta"
)

const defaultBaseURL = "https://secdb.nttzen.cloud"

var userAgent = fmt.Sprintf("secdb-cli/%s (+https://github.com/giterlizzi/secdb-cli)", meta.Version)

// Client is an HTTP client for the ZEN SecDB API.
type Client struct {
	baseURL    string
	webURL     string
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
		httpClient: &http.Client{Timeout: 120 * time.Second, CheckRedirect: checkRedirect},
	}
}

// apiKeyHeader carries the API key on every request.
const apiKeyHeader = "X-API-KEY"

// maxRedirects is the same limit as net/http's default policy.
const maxRedirects = 10

// checkRedirect follows a redirect like net/http does, but drops the API key
// when the redirect leaves the original scheme and host. net/http strips only
// Authorization and Cookie on a cross-host redirect, so X-API-KEY would
// otherwise reach the new host, in clear text after an https → http downgrade.
func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return fmt.Errorf("stopped after %d redirects", maxRedirects)
	}
	if orig := via[0].URL; req.URL.Scheme != orig.Scheme || req.URL.Host != orig.Host {
		req.Header.Del(apiKeyHeader)
	}
	return nil
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
// client for chaining. It doesn't validate the value: cmd checks --base-url with
// ValidateBaseURL first.
func (c *Client) WithBaseURL(baseURL string) *Client {
	if baseURL != "" {
		c.baseURL = strings.TrimRight(baseURL, "/")
	}
	return c
}

// WithWebURL sets the base of the web-GUI permalinks (no-op when empty) and
// returns the client for chaining. Like WithBaseURL, it doesn't validate the
// value. Needed only when the API is reached through a proxy, so the GUI isn't on
// the API host.
func (c *Client) WithWebURL(webURL string) *Client {
	if webURL != "" {
		c.webURL = strings.TrimRight(webURL, "/")
	}
	return c
}

// ValidateBaseURL checks a --base-url value and returns it normalized (lowercase
// scheme, no trailing slash); an empty value is returned as is, meaning "keep the
// default". Only an absolute http(s) URL with a host is accepted, without
// credentials, query or fragment, since the endpoint paths are appended to it.
func ValidateBaseURL(baseURL string) (string, error) {
	if baseURL == "" {
		return "", nil
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		// url.Error quotes the whole URL, which the caller already does.
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err
		}
		return "", err
	}

	switch {
	case u.Scheme != "http" && u.Scheme != "https":
		return "", errors.New("must be an absolute http(s) URL, e.g. https://secdb.nttzen.cloud")
	case u.Hostname() == "":
		return "", errors.New("missing host")
	case u.User != nil:
		return "", errors.New("credentials are not allowed")
	case strings.ContainsAny(baseURL, "?#"):
		return "", errors.New("query and fragment are not allowed")
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return "", fmt.Errorf("invalid port %q", p)
		}
	}

	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	return u.String(), nil
}

// IsLoopback reports whether the (validated) base URL points to the local
// machine: "localhost" or a loopback IP.
func IsLoopback(baseURL string) bool {
	u, err := url.Parse(baseURL)
	if err != nil {
		return false
	}
	h := u.Hostname()
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// BaseURL returns the configured API base URL (no trailing slash), where the
// requests go. For links meant for a person, use WebURL.
func (c *Client) BaseURL() string {
	return c.baseURL
}

// WebURL returns the base of the web-GUI permalinks (no trailing slash), e.g.
// weblink.CVE(WebURL(), id): the --web-url when set, else the API base URL,
// since the ZEN SecDB GUI shares the API host unless a proxy sits in between.
func (c *Client) WebURL() string {
	if c.webURL != "" {
		return c.webURL
	}
	return c.baseURL
}

func (c *Client) request(req *http.Request) (Response, error) {

	req.Header = http.Header{
		"Content-Type": {"application/json"},
		"User-Agent":   {userAgent},
	}

	if c.apiKey != "" {
		req.Header.Set(apiKeyHeader, c.apiKey)
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
