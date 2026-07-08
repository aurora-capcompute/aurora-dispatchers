package openaillm

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aurora-capcompute/aurora-dispatchers/builtin"
	"github.com/aurora-capcompute/aurora-dispatchers/registry"
)

func TestCapabilitySchemasAreValidJSON(t *testing.T) {
	for name, schema := range schemas {
		if !json.Valid(schema) {
			t.Fatalf("%s schema is invalid JSON", name)
		}
	}
}

func TestMatchesSyscall(t *testing.T) {
	reg := Registration{}
	if !reg.Matches("core.openaiApi") {
		t.Fatal("should match core.openaiApi")
	}
	if reg.Matches("openai.chat") {
		t.Fatal("must match the syscall, not an operation name")
	}
}

// A core.openaiApi grant publishes exactly one capability, named for the
// syscall, whose input schema is a oneOf over the granted operations.
func TestConfigurePublishesOneCapability(t *testing.T) {
	raw := json.RawMessage(`{"base_url":"https://api.openai.com/v1","api_key":"sk-test","capabilities":[{"operation":"chat"},{"operation":"models"}]}`)
	var config builtin.Config
	if err := (Registration{}).Configure(context.Background(), raw, registry.Services{}, &config); err != nil {
		t.Fatalf("configure: %v", err)
	}
	if len(config.Capabilities) != 1 || config.Capabilities[0].Name != SyscallType {
		t.Fatalf("capabilities = %+v, want one named %s", config.Capabilities, SyscallType)
	}
	schema := string(config.Capabilities[0].InputSchema)
	if !strings.Contains(schema, `"oneOf"`) || !strings.Contains(schema, `"chat"`) || !strings.Contains(schema, `"models"`) {
		t.Fatalf("input schema is not a oneOf over the granted operations: %s", schema)
	}
	if len(config.Handlers) != 1 || !config.Handlers[0].Handles(SyscallType) {
		t.Fatalf("handler must route by the capability name %s", SyscallType)
	}
}

func TestConfigureRequiresOperations(t *testing.T) {
	raw := json.RawMessage(`{"base_url":"https://api.openai.com/v1","api_key":"sk-test"}`)
	var config builtin.Config
	if err := (Registration{}).Configure(context.Background(), raw, registry.Services{}, &config); err == nil {
		t.Fatal("expected error when no operations are granted")
	}
	bad := json.RawMessage(`{"api_key":"sk-test","capabilities":[{"operation":"nope"}]}`)
	if err := (Registration{}).Configure(context.Background(), bad, registry.Services{}, &config); err == nil {
		t.Fatal("expected error for an unknown operation")
	}
}
