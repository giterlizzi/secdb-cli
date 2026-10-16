// SPDX-License-Identifier: Apache-2.0

package notify

// webhookEnv holds the generic webhook endpoint URL.
const webhookEnv = "SECDB_WEBHOOK_URL"

// webhook posts the Message as JSON to a generic HTTP endpoint. It is the
// simplest provider and the fallback for anything without a dedicated one
// (custom receivers, automation tools such as n8n or Zapier). It is stateless:
// it reads and validates its configuration in Send.
type webhook struct{}

func (webhook) Name() string { return "webhook" }

func (webhook) Send(msg Message) error {
	return postJSON("webhook", webhookEnv, msg)
}
