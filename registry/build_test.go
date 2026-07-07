package registry_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/aurora-capcompute/aurora-dispatchers/internet"
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
