// Package registry assembles built-in capability drivers: it selects a
// registration by the granted syscall and lets it publish that driver's
// handlers and capability schemas into a builtin.Config. The manifest names
// nothing — every capability name is canonical to its driver.
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
	// Tenant identifies whose memory space core.memory grants open.
	Tenant string
	// MemoryStore is the durable KV store behind core.memory grants.
	MemoryStore memory.Store
}

// Registration builds a leaf I/O driver for one syscall. A registration is
// selected by the granted syscall; the capability names it publishes are
// canonical to the driver (memory.get/put/list, internet.fetch, openai.*) —
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
// menu.
type Entry struct {
	Syscall  string
	Settings json.RawMessage
	Hidden   bool
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
		// A hidden grant hides every capability it publishes (e.g. the LLM
		// publishes openai.* operations under a hidden entry).
		if entry.Hidden {
			for i := before; i < len(config.Capabilities); i++ {
				config.Capabilities[i].Hidden = true
			}
		}
	}
	return config, nil
}

func (r *Registry) selectFor(syscall string) Registration {
	for _, registration := range r.registrations {
		if registration.Matches(syscall) {
			return registration
		}
	}
	return nil
}
