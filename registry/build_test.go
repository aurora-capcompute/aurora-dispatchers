package registry_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/aurora-capcompute/aurora-dispatchers/internet"
	"github.com/aurora-capcompute/aurora-dispatchers/memory"
	"github.com/aurora-capcompute/aurora-dispatchers/registry"
)

// Build selects a registration by the granted syscall; the capability it
// publishes and the handler it binds carry the driver's canonical name — the
// manifest names nothing.
func TestBuildPublishesCanonicalNames(t *testing.T) {
	reg := registry.Default()
	settings := json.RawMessage(`{"permissions":[{"methods":["GET"],"domain":"example.com"}]}`)
	config, err := reg.Build(context.Background(),
		[]registry.Entry{{Syscall: "core.internet", Settings: settings}}, registry.Services{})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(config.Capabilities) != 1 || config.Capabilities[0].Name != internet.Capability {
		t.Fatalf("capabilities = %+v, want one named %s", config.Capabilities, internet.Capability)
	}
	if len(config.Handlers) != 1 || !config.Handlers[0].Handles(internet.Capability) {
		t.Fatalf("handler does not handle %s", internet.Capability)
	}
	if config.Handlers[0].Handles("core.internet") {
		t.Fatal("handler must route by the canonical capability name, not the syscall")
	}
}

func TestBuildRejectsUnknownSyscall(t *testing.T) {
	reg := registry.Default()
	_, err := reg.Build(context.Background(), []registry.Entry{{Syscall: "core.bogus"}}, registry.Services{})
	if err == nil {
		t.Fatal("expected error for unknown syscall")
	}
}

// Build stamps the grant's data-flow policy (hidden/labels/forbid) onto every
// capability it publishes — the source labels the flow monitor accumulates and
// the forbid set it enforces.
func TestBuildStampsGrantPolicyOnEveryCapability(t *testing.T) {
	reg := registry.Default()

	// A single-capability source grant: hidden + labels + forbid all applied.
	config, err := reg.Build(context.Background(), []registry.Entry{{
		Syscall:  "core.internet",
		Settings: json.RawMessage(`{"permissions":[{"methods":["GET"],"domain":"example.com"}]}`),
		Hidden:   true,
		Labels:   []string{"untrusted_web"},
		Forbid:   []string{"secret"},
	}}, registry.Services{})
	if err != nil {
		t.Fatalf("build internet: %v", err)
	}
	if len(config.Capabilities) != 1 {
		t.Fatalf("capabilities = %+v", config.Capabilities)
	}
	published := config.Capabilities[0]
	if !published.Hidden {
		t.Error("Hidden not applied")
	}
	if len(published.Labels) != 1 || published.Labels[0] != "untrusted_web" {
		t.Errorf("labels = %v, want [untrusted_web]", published.Labels)
	}
	if len(published.Forbid) != 1 || published.Forbid[0] != "secret" {
		t.Errorf("forbid = %v, want [secret]", published.Forbid)
	}

	// A multi-capability sink grant: the forbid reaches every published op.
	config, err = reg.Build(context.Background(), []registry.Entry{{
		Syscall: "core.memory",
		Forbid:  []string{"untrusted_web"},
	}}, registry.Services{Tenant: "acme", MemoryStore: memory.NewMapStore()})
	if err != nil {
		t.Fatalf("build memory: %v", err)
	}
	if len(config.Capabilities) != 3 {
		t.Fatalf("memory should publish 3 capabilities, got %d", len(config.Capabilities))
	}
	for _, published := range config.Capabilities {
		if len(published.Forbid) != 1 || published.Forbid[0] != "untrusted_web" {
			t.Errorf("%s forbid = %v, want [untrusted_web]", published.Name, published.Forbid)
		}
	}
}
