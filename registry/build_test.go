package registry_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/aurora-capcompute/aurora-dispatchers/internet"
	"github.com/aurora-capcompute/aurora-dispatchers/memory"
	"github.com/aurora-capcompute/aurora-dispatchers/registry"
)

// Build selects a registration by the granted syscall and publishes exactly one
// capability, named for that syscall — the operations are cases of its ADT, not
// separate names.
func TestBuildPublishesOneCapabilityPerGrant(t *testing.T) {
	reg := registry.Default()
	config := json.RawMessage(`{"capabilities":[{"methods":["GET"],"domain":"example.com"}]}`)
	built, err := reg.Build(context.Background(),
		[]registry.Entry{{Syscall: "core.internet", Config: config}}, registry.Services{})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(built.Capabilities) != 1 || built.Capabilities[0].Name != internet.Capability {
		t.Fatalf("capabilities = %+v, want one named %s", built.Capabilities, internet.Capability)
	}
	if built.Capabilities[0].Name != "core.internet" {
		t.Fatalf("capability name = %q, want the syscall name core.internet", built.Capabilities[0].Name)
	}
	if len(built.Handlers) != 1 || !built.Handlers[0].Handles("core.internet") {
		t.Fatalf("handler must route by the capability name core.internet")
	}
}

func TestBuildRejectsUnknownSyscall(t *testing.T) {
	reg := registry.Default()
	_, err := reg.Build(context.Background(), []registry.Entry{{Syscall: "core.bogus"}}, registry.Services{})
	if err == nil {
		t.Fatal("expected error for unknown syscall")
	}
}

// A hidden grant keeps its published capability off the discoverable menu.
func TestBuildAppliesHidden(t *testing.T) {
	services := registry.Services{Tenant: "acme", MemoryStore: memory.NewMapStore()}
	built, err := registry.Default().Build(context.Background(), []registry.Entry{{
		Syscall: "core.memory",
		Config:  json.RawMessage(`{"capabilities":[{"operation":"get"}]}`),
		Hidden:  true,
	}}, services)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(built.Capabilities) != 1 || !built.Capabilities[0].Hidden {
		t.Fatalf("capabilities = %+v, want one hidden", built.Capabilities)
	}
}
