// Package registry assembles built-in capability drivers: it selects a
// registration by the granted syscall and folds what that registration
// publishes into one capability.Table.
package registry

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aurora-capcompute/aurora-capcompute/capability"
)

// Services are the host-side facts a registration needs to configure a driver —
// never guest-supplied.
type Services struct {
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
	Configure(ctx context.Context, config json.RawMessage, services Services) (capability.Family, error)
}

type Registry struct {
	registrations []Registration
}

func New(registrations ...Registration) *Registry {
	return &Registry{registrations: append([]Registration(nil), registrations...)}
}

// ValidateConfig checks one leaf grant's config by building what the spawn would
// build and throwing it away, so the door check and the build cannot disagree
// about what a valid config is. Building is safe to do twice: a Configure
// resolves host-held secrets and assembles clients, but performs no I/O and
// depends on no process credential.
func (r *Registry) ValidateConfig(ctx context.Context, syscall string, config json.RawMessage, services Services) error {
	selected := r.selectFor(syscall)
	if selected == nil {
		return fmt.Errorf("unsupported syscall %q", syscall)
	}
	_, err := selected.Configure(ctx, config, services)
	return err
}

// Entry is one leaf grant to build. Syscall selects the registration; Config is
// the grant's driver configuration — the `capabilities` list and any family-wide
// knobs — opaque to the runtime and interpreted by the driver. Hidden keeps the
// published capability dispatchable but off the program's discoverable menu.
type Entry struct {
	Syscall string
	Config  json.RawMessage
	Hidden  bool
}

func (r *Registry) Build(ctx context.Context, entries []Entry, services Services) (*capability.Table, error) {
	table := capability.NewTable()
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
