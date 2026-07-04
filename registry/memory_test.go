package registry_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aurora-capcompute/aurora-dispatchers/memory"
	"github.com/aurora-capcompute/aurora-dispatchers/registry"
	"github.com/aurora-capcompute/capcompute/sys"
)

func TestMemoryRegistrationPublishesOperations(t *testing.T) {
	config, err := registry.Default().Build(context.Background(),
		[]registry.Entry{{Name: "mem", Type: "core.memory", Settings: json.RawMessage(`{"subtree":"notes","require_approval_on_put":true}`)}},
		registry.Services{Tenant: "acme", MemoryStore: memory.NewMapStore()},
	)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	names := make(map[string]sys.Capability, len(config.Capabilities))
	for _, capability := range config.Capabilities {
		names[capability.Name] = capability
	}
	for _, want := range []string{"mem.get", "mem.put", "mem.list"} {
		capability, ok := names[want]
		if !ok {
			t.Fatalf("capability %q not published: %v", want, names)
		}
		if len(capability.InputSchema) == 0 {
			t.Fatalf("capability %q has no input schema", want)
		}
	}
	if len(config.Handlers) != 1 || !config.Handlers[0].Handles("mem.put") {
		t.Fatalf("handlers = %+v", config.Handlers)
	}
}

func TestMemoryRegistrationRequiresServices(t *testing.T) {
	entries := []registry.Entry{{Name: "mem", Type: "core.memory"}}

	if _, err := registry.Default().Build(context.Background(), entries,
		registry.Services{MemoryStore: memory.NewMapStore()}); err == nil || !strings.Contains(err.Error(), "Tenant") {
		t.Fatalf("err = %v, want missing-tenant error", err)
	}
	if _, err := registry.Default().Build(context.Background(), entries,
		registry.Services{Tenant: "acme"}); err == nil || !strings.Contains(err.Error(), "MemoryStore") {
		t.Fatalf("err = %v, want missing-store error", err)
	}
}

func TestMemoryRegistrationRejectsBadSubtree(t *testing.T) {
	for _, subtree := range []string{"/abs", "trail/", "a/../b"} {
		_, err := registry.Default().Normalize("core.memory", json.RawMessage(`{"subtree":"`+subtree+`"}`))
		if err == nil {
			t.Fatalf("subtree %q accepted", subtree)
		}
	}
	if _, err := registry.Default().Normalize("core.memory", json.RawMessage(`{"subtree":"notes/work"}`)); err != nil {
		t.Fatalf("valid subtree rejected: %v", err)
	}
}
