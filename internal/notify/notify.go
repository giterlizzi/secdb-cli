// SPDX-License-Identifier: Apache-2.0

// Package notify delivers an audit summary to one or more destinations (a
// generic webhook, Slack and Microsoft Teams today; email later). Providers are
// configured from the environment (v1) and listed in a static registry,
// mirroring the parser registry in internal/manifest: adding a provider is a
// new file plus an entry in the registry map, nothing else.
package notify

import (
	"fmt"
	"maps"
	"slices"
)

// Provider delivers a Message to one destination. Implementations are stateless
// zero values registered in the registry; each reads its configuration from the
// environment in Send.
type Provider interface {
	Name() string
	Send(msg Message) error
}

// registry lists the known providers by name (same role as the `parsers` slice
// in internal/manifest). Adding a provider is a new file plus an entry here.
// Providers are stateless: they read and validate their configuration in Send,
// so a zero value is a usable, ready-to-register instance.
var registry = map[string]Provider{
	"webhook": webhook{},
	"slack":   slack{},
	"teams":   teams{},
}

// Available returns the known provider names, sorted.
func Available() []string {
	return slices.Sorted(maps.Keys(registry))
}

// Resolve selects the providers to notify. With no names it returns every known
// provider; with names it returns those named, erroring on an unknown name. A
// provider missing its configuration is not rejected here: Send reports that, so
// one unconfigured provider never blocks the others (best-effort delivery).
func Resolve(names []string) ([]Provider, error) {
	if len(names) == 0 {
		names = Available()
	}

	providers := make([]Provider, 0, len(names))
	for _, name := range names {
		p, known := registry[name]
		if !known {
			return nil, fmt.Errorf("unknown notification provider %q (available: %v)", name, Available())
		}
		providers = append(providers, p)
	}
	return providers, nil
}

// Send delivers msg to each provider, best-effort: every provider is tried and
// the errors are collected (nil when all succeed), so a single broken endpoint
// never blocks the others or fails the CLI.
func Send(providers []Provider, msg Message) []error {
	var errs []error
	for _, p := range providers {
		if err := p.Send(msg); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p.Name(), err))
		}
	}
	return errs
}
