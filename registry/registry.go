// Package registry assembles built-in capability drivers: it selects a
// registration by the granted syscall and lets it publish that driver's handler
// and one capability into a builtin.Config. The capability is named for the
// syscall (core.internet, core.memory, core.openaiApi): a leaf grant is an ADT
// family whose operations are cases of one capability, discriminated inside the
// call args — never separate names. The grant's data-flow policy (labels/taints)
// rides on each operation and is enforced by the driver itself, per call.
package registry

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aurora-capcompute/aurora-dispatchers/builtin"
	"github.com/aurora-capcompute/aurora-dispatchers/memory"
)

// Services are the host-side facts a registration needs to configure a driver —
// never guest-supplied.
type Services struct {
	// Tenant identifies whose memory space core.memory grants open. It is the
	// absolute isolation boundary — no grant can reach another tenant.
	Tenant string
	// SessionID and ProcessID are the calling process's identity, taken from its
	// credential. They resolve core.memory's session/process scopes to their
	// physical key prefixes, so they are per-process (unlike the deployment-scoped
	// fields above) and must be set by the provider on each NewDispatcher.
	SessionID string
	ProcessID string
	// MemoryStore is the durable KV store behind core.memory grants.
	MemoryStore memory.Store
	// Secrets resolves manifest secret references (e.g. an injected
	// Authorization token, an api_key) to their host-held values. Nil means no
	// references may be used — a grant that references one fails to build.
	Secrets SecretResolver
	// AuditKey keys the credential fingerprints stamped on results (empty is
	// allowed; it yields a stable but unkeyed fingerprint).
	AuditKey []byte
}

// Registration builds a leaf I/O driver for one syscall. A registration is
// selected by the granted syscall and returns what it contributes: one entry per
// case of that syscall's ADT, the argument properties that name a case, and the
// one capability they add up to. It never sees the table — the assembler folds
// the contributions, which is what makes a duplicate a refusal rather than a
// first-wins.
type Registration interface {
	Matches(syscall string) bool
	Normalize(syscall string, config json.RawMessage) (json.RawMessage, error)
	Configure(ctx context.Context, config json.RawMessage, services Services) (builtin.Contribution, error)
}

type Registry struct {
	registrations []Registration
}

func New(registrations ...Registration) *Registry {
	return &Registry{registrations: append([]Registration(nil), registrations...)}
}

func (r *Registry) Normalize(syscall string, config json.RawMessage) (json.RawMessage, error) {
	if selected := r.selectFor(syscall); selected != nil {
		return selected.Normalize(syscall, config)
	}
	return nil, fmt.Errorf("unsupported syscall %q", syscall)
}

// Entry is one leaf grant to build. Syscall selects the registration; Config is
// the grant's driver configuration — the `capabilities` list and any family-wide
// knobs — opaque to the runtime and interpreted by the driver. Hidden keeps the
// published capability dispatchable but off the program's discoverable menu (the
// LLM driver publishes under a hidden entry, for instance).
type Entry struct {
	Syscall string
	Config  json.RawMessage
	Hidden  bool
}

func (r *Registry) Build(ctx context.Context, entries []Entry, services Services) (*builtin.Table, error) {
	table := builtin.NewTable()
	for _, entry := range entries {
		selected := r.selectFor(entry.Syscall)
		if selected == nil {
			return nil, fmt.Errorf("unsupported syscall %q", entry.Syscall)
		}
		contribution, err := selected.Configure(ctx, entry.Config, services)
		if err != nil {
			return nil, err
		}
		if err := table.Add(contribution); err != nil {
			return nil, err
		}
		// A family serves the syscall it was selected for and no other.
		for _, granted := range contribution.Entries {
			if granted.Key.Syscall != entry.Syscall {
				return nil, fmt.Errorf("%q contributed an operation on %q", entry.Syscall, granted.Key.Syscall)
			}
		}
		// A hidden grant keeps the capability it just contributed off the
		// discoverable menu; its operations stay dispatchable.
		if entry.Hidden {
			table.Hide(entry.Syscall)
		}
	}
	return table, nil
}

func (r *Registry) selectFor(syscall string) Registration {
	for _, registration := range r.registrations {
		if registration.Matches(syscall) {
			return registration
		}
	}
	return nil
}
