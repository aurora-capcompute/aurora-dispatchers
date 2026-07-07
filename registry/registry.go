// Package registry assembles built-in capability drivers: it selects a
// registration by the granted syscall and lets it publish that driver's
// handlers and capability schemas into a builtin.Config. The manifest names
// nothing — every capability name is canonical to its driver.
package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/aurora-capcompute/aurora-dispatchers/builtin"
	"github.com/aurora-capcompute/aurora-dispatchers/memory"
)

// Services are the host-side facts a registration needs to configure a driver —
// never guest-supplied.
type Services struct {
	// Tenant identifies whose memory space core.memory grants open.
	Tenant string
	// MemoryStore is the durable KV store behind core.memory grants.
	MemoryStore memory.Store
}

// Registration builds a leaf I/O driver for one syscall. A registration is
// selected by the granted syscall; the capability names it publishes are
// canonical to the driver (memory.get/put/list, net.http, openai.*) —
// the manifest names nothing.
type Registration interface {
	Matches(syscall string) bool
	Normalize(syscall string, settings json.RawMessage) (json.RawMessage, error)
	Configure(ctx context.Context, settings json.RawMessage, services Services, config *builtin.Config) error
}

type Registry struct {
	registrations []Registration
}

func New(registrations ...Registration) *Registry {
	return &Registry{registrations: append([]Registration(nil), registrations...)}
}

// Default is the credential-free built-in set: the internet and memory drivers.
// Network-credentialed drivers (e.g. openaillm) are added explicitly by the
// assembly.
//
// Try-Confirm/Cancel is deliberately not a driver. A reservation is a real
// write to the participant that owns the resource — the third-party system
// every reader treats as the source of truth — so it is an ordinary dispatch:
// reserve, register the release with sys.compensate (the runtime guarantees it
// runs if the section aborts or fails), confirm as the last call before
// sys.commit. Pending state, and any expiry policy, belong to the resource
// owner (Pardon & Pautasso's RESTful TCC puts them on the participant); an
// orchestrator-side hold table would be a reservation no other booker can see.
func Default() *Registry {
	return New(InternetRegistration{}, MemoryRegistration{})
}

func (r *Registry) Normalize(syscall string, settings json.RawMessage) (json.RawMessage, error) {
	if selected := r.selectFor(syscall); selected != nil {
		return selected.Normalize(syscall, settings)
	}
	return nil, fmt.Errorf("unsupported syscall %q", syscall)
}

// Entry is one leaf grant to build: `Syscall` selects the registration.
// `Hidden` keeps the grant dispatchable but off the program's discoverable
// menu. `Labels` and `Forbid` are the grant's data-flow policy, keyed by
// published capability name (the key "*" applies to every capability the grant
// publishes) — Labels are the source classes results carry, Forbid lists labels
// that may not flow into the operation's calls.
type Entry struct {
	Syscall  string
	Settings json.RawMessage
	Hidden   bool
	Labels   map[string][]string
	Forbid   map[string][]string
}

func (r *Registry) Build(ctx context.Context, entries []Entry, services Services) (builtin.Config, error) {
	var config builtin.Config
	for _, entry := range entries {
		selected := r.selectFor(entry.Syscall)
		if selected == nil {
			return builtin.Config{}, fmt.Errorf("unsupported syscall %q", entry.Syscall)
		}
		before := len(config.Capabilities)
		if err := selected.Configure(ctx, entry.Settings, services, &config); err != nil {
			return builtin.Config{}, err
		}
		// Apply the grant's cross-cutting policy to every capability it just
		// published: a hidden grant keeps them off the discoverable menu (e.g.
		// the LLM publishes openai.* under a hidden entry); its data-flow
		// labels/forbid ("*" plus the per-operation entry) drive the kernel's
		// provenance monitor.
		published := make(map[string]struct{}, len(config.Capabilities)-before)
		for i := before; i < len(config.Capabilities); i++ {
			name := config.Capabilities[i].Name
			published[name] = struct{}{}
			if entry.Hidden {
				config.Capabilities[i].Hidden = true
			}
			config.Capabilities[i].Labels = applyFlow(config.Capabilities[i].Labels, entry.Labels, name)
			config.Capabilities[i].Forbid = applyFlow(config.Capabilities[i].Forbid, entry.Forbid, name)
		}
		if err := checkFlowOps("labels", entry.Labels, published); err != nil {
			return builtin.Config{}, fmt.Errorf("%q: %w", entry.Syscall, err)
		}
		if err := checkFlowOps("forbid", entry.Forbid, published); err != nil {
			return builtin.Config{}, fmt.Errorf("%q: %w", entry.Syscall, err)
		}
	}
	return config, nil
}

// applyFlow adds a policy's wildcard ("*") labels and the labels targeting the
// named operation to a capability's existing set.
func applyFlow(existing []string, policy map[string][]string, name string) []string {
	existing = append(existing, policy["*"]...)
	existing = append(existing, policy[name]...)
	return existing
}

// checkFlowOps rejects a per-operation key that names no capability the grant
// published — a typo there would otherwise silently leave a source unlabelled
// or a sink unprotected.
func checkFlowOps(what string, policy map[string][]string, published map[string]struct{}) error {
	for op := range policy {
		if op == "*" {
			continue
		}
		if _, ok := published[op]; !ok {
			names := make([]string, 0, len(published))
			for name := range published {
				names = append(names, name)
			}
			sort.Strings(names)
			return fmt.Errorf("%s targets operation %q, which this grant does not publish (publishes: %s)",
				what, op, strings.Join(names, ", "))
		}
	}
	return nil
}

func (r *Registry) selectFor(syscall string) Registration {
	for _, registration := range r.registrations {
		if registration.Matches(syscall) {
			return registration
		}
	}
	return nil
}
