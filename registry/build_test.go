package registry_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/aurora-capcompute/aurora-dispatchers/internet"
	"github.com/aurora-capcompute/aurora-dispatchers/registry"
	"github.com/aurora-capcompute/aurora-dispatchers/scratch"
)

// Build selects a registration by the granted syscall and publishes exactly one
// capability, named for that syscall — the operations are cases of its ADT, not
// separate names.
func TestBuildPublishesOneCapabilityPerGrant(t *testing.T) {
	reg := registry.New(internet.Registration{}, scratch.Registration{})
	config := json.RawMessage(`{"capabilities":[{"methods":["GET"],"domain":"example.com"}]}`)
	built, err := reg.Build(context.Background(),
		[]registry.Entry{{Syscall: "core.internet", Config: config}}, registry.Services{})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(built.Descriptors()) != 1 || built.Descriptors()[0].Name != internet.Capability {
		t.Fatalf("capabilities = %+v, want one named %s", built.Descriptors(), internet.Capability)
	}
	if built.Descriptors()[0].Name != "core.internet" {
		t.Fatalf("capability name = %q, want the syscall name core.internet", built.Descriptors()[0].Name)
	}
	if len(built.Operations("core.internet")) == 0 {
		t.Fatalf("handler must route by the capability name core.internet")
	}
}

func TestBuildRejectsUnknownSyscall(t *testing.T) {
	reg := registry.New(internet.Registration{}, scratch.Registration{})
	_, err := reg.Build(context.Background(), []registry.Entry{{Syscall: "core.bogus"}}, registry.Services{})
	if err == nil {
		t.Fatal("expected error for unknown syscall")
	}
}

// A hidden grant keeps its published capability off the discoverable menu.
func TestBuildAppliesHidden(t *testing.T) {
	services := registry.Services{}
	built, err := registry.New(internet.Registration{}, scratch.Registration{}).Build(context.Background(), []registry.Entry{{
		Syscall: "core.scratch",
		Config:  json.RawMessage(`{"capabilities":[{"operation":"get"}]}`),
		Hidden:  true,
	}}, services)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(built.Descriptors()) != 1 || !built.Descriptors()[0].Hidden {
		t.Fatalf("capabilities = %+v, want one hidden", built.Descriptors())
	}
}
