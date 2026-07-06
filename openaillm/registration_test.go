package openaillm

import (
	"context"
	"encoding/json"
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

func TestMatchesType(t *testing.T) {
	reg := Registration{}
	if !reg.Matches("core.openaiApi") {
		t.Fatal("should match core.openaiApi")
	}
	if reg.Matches("openai.chat") {
		t.Fatal("must match by type, not an operation name")
	}
}

// One core.openaiApi tool publishes the fixed openai.* operations the program
// calls by name; the local manifest name is cosmetic.
func TestConfigurePublishesAllOperations(t *testing.T) {
	raw := json.RawMessage(`{"base_url":"https://api.openai.com/v1","api_key":"sk-test"}`)
	var config builtin.Config
	if err := (Registration{}).Configure(context.Background(), raw, registry.Services{}, &config); err != nil {
		t.Fatalf("configure: %v", err)
	}
	if len(config.Capabilities) != len(validOperations) {
		t.Fatalf("capabilities = %d, want %d", len(config.Capabilities), len(validOperations))
	}
	got := map[string]bool{}
	for _, c := range config.Capabilities {
		got[c.Name] = true
	}
	for op := range validOperations {
		if !got[op] {
			t.Fatalf("missing capability %q; got %+v", op, config.Capabilities)
		}
	}
	if len(config.Handlers) != 1 || !config.Handlers[0].Handles("openai.chat") {
		t.Fatal("handler must handle the openai.chat operation")
	}
}
