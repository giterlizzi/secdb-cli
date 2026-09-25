// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
)

// slackEnv holds the Slack Incoming Webhook URL.
const slackEnv = "SECDB_SLACK_WEBHOOK"

// Slack Block Kit has no colored bar, so this provider uses the (legacy but
// supported) attachment format, like GitLab and Grafana do. The severity
// color/order live in severity.go, shared with the other providers.

// slack posts the Message to a Slack Incoming Webhook as a colored attachment.
type slack struct{}

func (slack) Name() string { return "slack" }

func (slack) Send(msg Message) error {
	endpoint := os.Getenv(slackEnv)
	if endpoint == "" {
		return fmt.Errorf("%s not set", slackEnv)
	}

	body, err := json.Marshal(buildSlackMessage(msg))
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
		return fmt.Errorf("slack returned %s", resp.Status)
	}
	return nil
}

type slackMessage struct {
	Text        string            `json:"text"`
	Attachments []slackAttachment `json:"attachments,omitempty"`
}

type slackAttachment struct {
	Color     string       `json:"color,omitempty"`
	Title     string       `json:"title,omitempty"`
	TitleLink string       `json:"title_link,omitempty"`
	Text      string       `json:"text,omitempty"`
	Fields    []slackField `json:"fields,omitempty"`
	Fallback  string       `json:"fallback,omitempty"`
}

type slackField struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

// buildSlackMessage maps a Message to the Slack payload.
func buildSlackMessage(msg Message) slackMessage {
	// Deep link: prefer the CI run, fall back to the SecDB instance.
	link := msg.CI.RunURL
	if link == "" {
		link = msg.BaseURL
	}

	// Per-severity counts as short fields, most severe first.
	var fields []slackField
	for _, sev := range severityOrder {
		if n := msg.Counts[sev]; n > 0 {
			fields = append(fields, slackField{
				Title: strings.ToUpper(sev[:1]) + sev[1:],
				Value: strconv.Itoa(n),
				Short: true,
			})
		}
	}

	// A short list of the top findings (already capped to MaxFindings by the
	// builder); note the overflow when present.
	var lines []string
	for _, f := range msg.Findings {
		line := f.Name
		if len(f.CVEs) > 0 {
			line += " (" + strings.Join(f.CVEs, ", ") + ")"
		}
		if target := f.PURL; target != "" {
			line += " - " + target
		} else if f.Package != "" {
			line += " - " + f.Package
		}
		lines = append(lines, line)
	}
	if msg.Truncated > 0 {
		lines = append(lines, fmt.Sprintf("... and %d more", msg.Truncated))
	}

	return slackMessage{
		Text: msg.Title,
		Attachments: []slackAttachment{{
			Color:     colorFor(msg.Overall),
			Title:     fmt.Sprintf("%s (%d findings)", msg.Source, msg.Total),
			TitleLink: link,
			Text:      strings.Join(lines, "\n"),
			Fields:    fields,
			Fallback:  msg.Title,
		}},
	}
}
