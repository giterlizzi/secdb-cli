// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"strconv"
	"strings"
)

// teamsEnv holds the Microsoft Teams incoming webhook URL (a Power Automate
// "Workflows" HTTP trigger).
const teamsEnv = "SECDB_TEAMS_WEBHOOK"

// Microsoft retired the Office 365 connectors (the legacy MessageCard format
// with themeColor), so this provider targets the supported path: a Power
// Automate Workflows webhook, which expects an Adaptive Card wrapped in a
// {type:"message", attachments:[...]} envelope. Adaptive Cards have no arbitrary
// color, so the severity maps to their fixed palette (see adaptiveColor) rather
// than the hex in severity.go.

// teams posts the Message to a Teams Workflows webhook as an Adaptive Card.
type teams struct{}

func (teams) Name() string { return "teams" }

func (teams) Send(msg Message) error {
	return postJSON("teams", teamsEnv, buildTeamsMessage(msg))
}

// teamsMessage is the Workflows envelope: an Adaptive Card attachment.
type teamsMessage struct {
	Type        string            `json:"type"` // "message"
	Attachments []teamsAttachment `json:"attachments"`
}

type teamsAttachment struct {
	ContentType string       `json:"contentType"` // adaptive card content type
	Content     adaptiveCard `json:"content"`
}

type adaptiveCard struct {
	Schema  string            `json:"$schema"`
	Type    string            `json:"type"`    // "AdaptiveCard"
	Version string            `json:"version"` // "1.5"
	Body    []any             `json:"body"`
	Actions []adaptiveOpenURL `json:"actions,omitempty"`
}

// adaptiveTextBlock is an Adaptive Card TextBlock element.
type adaptiveTextBlock struct {
	Type     string `json:"type"` // "TextBlock"
	Text     string `json:"text"`
	Wrap     bool   `json:"wrap"`
	Weight   string `json:"weight,omitempty"` // "Bolder"
	Size     string `json:"size,omitempty"`   // "Large"
	Color    string `json:"color,omitempty"`  // "Attention", "Warning", "Accent", ...
	IsSubtle bool   `json:"isSubtle,omitempty"`
}

// adaptiveFactSet is an Adaptive Card FactSet element.
type adaptiveFactSet struct {
	Type  string         `json:"type"` // "FactSet"
	Facts []adaptiveFact `json:"facts"`
}

type adaptiveFact struct {
	Title string `json:"title"`
	Value string `json:"value"`
}

// adaptiveOpenURL is an Action.OpenUrl action (a link button).
type adaptiveOpenURL struct {
	Type  string `json:"type"` // "Action.OpenUrl"
	Title string `json:"title"`
	URL   string `json:"url"`
}

// adaptiveContentType is the Adaptive Card attachment content type Teams expects.
const adaptiveContentType = "application/vnd.microsoft.card.adaptive"

// adaptiveColor maps a severity to an Adaptive Card color name (its palette has
// no arbitrary hex), or empty for the default color when the severity is unknown.
func adaptiveColor(severity string) string {
	switch severity {
	case "critical", "high":
		return "Attention"
	case "medium", "low":
		return "Warning"
	case "info":
		return "Accent"
	default:
		return ""
	}
}

// buildTeamsMessage maps a Message to the Teams Adaptive Card payload.
func buildTeamsMessage(msg Message) teamsMessage {
	body := []any{
		adaptiveTextBlock{
			Type:   "TextBlock",
			Text:   msg.Title,
			Wrap:   true,
			Weight: "Bolder",
			Size:   "Large",
			Color:  adaptiveColor(msg.Overall),
		},
		adaptiveTextBlock{
			Type:     "TextBlock",
			Text:     msg.summary(),
			Wrap:     true,
			IsSubtle: true,
		},
	}

	// Per-severity counts as facts, most severe first.
	var facts []adaptiveFact
	for _, c := range severityCountsSorted(msg.Counts) {
		facts = append(facts, adaptiveFact{Title: c.Label, Value: strconv.Itoa(c.Count)})
	}
	if len(facts) > 0 {
		body = append(body, adaptiveFactSet{Type: "FactSet", Facts: facts})
	}

	if lines := msg.renderFindings(); len(lines) > 0 {
		body = append(body, adaptiveTextBlock{
			Type: "TextBlock",
			Text: strings.Join(lines, "\n\n"),
			Wrap: true,
		})
	}

	var actions []adaptiveOpenURL
	if link := msg.detailsURL(); link != "" {
		actions = append(actions, adaptiveOpenURL{
			Type:  "Action.OpenUrl",
			Title: "View details",
			URL:   link,
		})
	}

	return teamsMessage{
		Type: "message",
		Attachments: []teamsAttachment{{
			ContentType: adaptiveContentType,
			Content: adaptiveCard{
				Schema:  "http://adaptivecards.io/schemas/adaptive-card.json",
				Type:    "AdaptiveCard",
				Version: "1.5",
				Body:    body,
				Actions: actions,
			},
		}},
	}
}
