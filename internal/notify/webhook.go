// SPDX-License-Identifier: Apache-2.0

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

// webhookEnv holds the generic webhook endpoint URL.
const webhookEnv = "SECDB_WEBHOOK_URL"

// httpClient is shared by the HTTP-based providers.
var httpClient = &http.Client{Timeout: 15 * time.Second}

// webhook posts the Message as JSON to a generic HTTP endpoint. It is the
// simplest provider and the fallback for anything without a dedicated one
// (custom receivers, automation tools such as n8n or Zapier). It is stateless:
// it reads and validates its configuration in Send.
type webhook struct{}

func (webhook) Name() string { return "webhook" }

func (webhook) Send(msg Message) error {
	endpoint := os.Getenv(webhookEnv)
	if endpoint == "" {
		return fmt.Errorf("%s not set", webhookEnv)
	}

	body, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return redactURL(err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return redactURL(err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %s", resp.Status)
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
