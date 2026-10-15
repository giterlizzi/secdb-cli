// SPDX-License-Identifier: Apache-2.0

// This file holds the HTTP delivery shared by the providers (webhook, slack,
// teams): each builds its own payload and hands it to postJSON.

package notify

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

// httpClient is shared by the HTTP-based providers.
var httpClient = &http.Client{Timeout: 15 * time.Second}

// postJSON marshals payload and POSTs it as JSON to the endpoint URL held in the
// given environment variable. It is the shared body of the HTTP providers
// (webhook, slack, teams): name is used in the returned error, and any endpoint
// URL is redacted so a secret-bearing webhook URL never reaches logs or stderr.
func postJSON(name, envVar string, payload any) error {
	endpoint := os.Getenv(envVar)
	if endpoint == "" {
		return fmt.Errorf("%s not set", envVar)
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	// endpoint is the operator's own webhook URL from the environment, not
	// remote input, so the SSRF taint finding below doesn't apply.
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body)) //nolint:gosec // G704: operator-configured endpoint
	if err != nil {
		return redactURL(err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req) //nolint:gosec // G704: operator-configured endpoint, see above
	if err != nil {
		return redactURL(err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%s returned %s", name, resp.Status)
	}
	return nil
}

// redactURL strips the endpoint URL that net/http wraps into *url.Error, so a
// secret-bearing webhook URL never reaches logs or stderr.
func redactURL(err error) error {
	if uerr, ok := errors.AsType[*url.Error](err); ok {
		return fmt.Errorf("%s request failed: %w", uerr.Op, uerr.Err)
	}
	return err
}
