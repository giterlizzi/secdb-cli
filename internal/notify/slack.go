// SPDX-License-Identifier: Apache-2.0

package notify

import (
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
	return postJSON("slack", slackEnv, buildSlackMessage(msg))
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
	// Per-severity counts as short fields, most severe first.
	var fields []slackField
	for _, c := range severityCountsSorted(msg.Counts) {
		fields = append(fields, slackField{
			Title: c.Label,
			Value: strconv.Itoa(c.Count),
			Short: true,
		})
	}

	return slackMessage{
		Text: msg.Title,
		Attachments: []slackAttachment{{
			Color:     severityColor[msg.Overall],
			Title:     msg.summary(),
			TitleLink: msg.detailsURL(),
			Text:      strings.Join(msg.renderFindings(), "\n"),
			Fields:    fields,
			Fallback:  msg.Title,
		}},
	}
}
