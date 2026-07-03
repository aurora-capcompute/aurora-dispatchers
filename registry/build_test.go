package registry_test

import (
	"context"
	"testing"

	"github.com/aurora-capcompute/aurora-dispatchers/registry"
)

// Build selects a registration by the tool's `type`, then publishes the
// capability and binds the handler under the tool's local `name`. The program
// routes by `name`, never by `type`.
func TestBuildRoutesByLocalName(t *testing.T) {
	reg := registry.Default()
	entries := []registry.Entry{
		{Name: "myTimer", Type: "core.timer"},
	}
	config, err := reg.Build(context.Background(), entries, registry.Services{})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(config.Capabilities) != 1 || config.Capabilities[0].Name != "myTimer" {
		t.Fatalf("capabilities = %+v, want one named myTimer", config.Capabilities)
	}
	if len(config.Handlers) != 1 || !config.Handlers[0].Handles("myTimer") {
		t.Fatal("handler does not handle the local name myTimer")
	}
	if config.Handlers[0].Handles("core.timer") || config.Handlers[0].Handles("timer.set") {
		t.Fatal("handler must route by local name, not by type or fixed capability name")
	}
}

// Two instances of the same type are addressable independently by name.
func TestBuildTwoInstancesOfSameType(t *testing.T) {
	reg := registry.Default()
	entries := []registry.Entry{
		{Name: "shortTimer", Type: "core.timer"},
		{Name: "longTimer", Type: "core.timer"},
	}
	config, err := reg.Build(context.Background(), entries, registry.Services{})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(config.Handlers) != 2 {
		t.Fatalf("handlers = %d, want 2", len(config.Handlers))
	}
	names := map[string]bool{}
	for _, c := range config.Capabilities {
		names[c.Name] = true
	}
	if !names["shortTimer"] || !names["longTimer"] {
		t.Fatalf("capabilities = %+v, want shortTimer and longTimer", config.Capabilities)
	}
}

func TestBuildRejectsUnknownType(t *testing.T) {
	reg := registry.Default()
	_, err := reg.Build(context.Background(), []registry.Entry{{Name: "x", Type: "core.bogus"}}, registry.Services{})
	if err == nil {
		t.Fatal("expected error for unknown type")
	}
}
