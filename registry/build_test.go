package registry_test

import (
	"context"
	"testing"

	"github.com/aurora-capcompute/aurora-dispatchers/registry"
	"github.com/aurora-capcompute/aurora-dispatchers/timer"
)

// Build selects a registration by the granted syscall; the capability it
// publishes and the handler it binds carry the driver's canonical name — the
// manifest names nothing.
func TestBuildPublishesCanonicalNames(t *testing.T) {
	reg := registry.Default()
	config, err := reg.Build(context.Background(), []registry.Entry{{Syscall: "core.timer"}}, registry.Services{})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(config.Capabilities) != 1 || config.Capabilities[0].Name != timer.Capability {
		t.Fatalf("capabilities = %+v, want one named %s", config.Capabilities, timer.Capability)
	}
	if len(config.Handlers) != 1 || !config.Handlers[0].Handles(timer.Capability) {
		t.Fatalf("handler does not handle %s", timer.Capability)
	}
	if config.Handlers[0].Handles("core.timer") {
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
