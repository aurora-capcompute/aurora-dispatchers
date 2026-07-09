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

// mapResolver is a test SecretResolver backed by a map.
type mapResolver map[string]string

func (m mapResolver) Resolve(name string) (string, bool) { v, ok := m[name]; return v, ok }

// The api_key may be a host-held reference resolved at activation. Normalize
// persists only the reference — the value never lands in the stored manifest.
func TestConfigureResolvesAPIKeyReference(t *testing.T) {
	raw := json.RawMessage(`{"base_url":"https://api.openai.com/v1","api_key":{"secret":"OPENAI_KEY"},"capabilities":[{"operation":"chat"}]}`)

	normalized, err := (Registration{}).Normalize("core.openaiApi", raw)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if !strings.Contains(string(normalized), `"secret":"OPENAI_KEY"`) {
		t.Fatalf("normalized dropped the api_key reference: %s", normalized)
	}
	if strings.Contains(string(normalized), "sk-real") {
		t.Fatalf("normalized leaked the resolved api_key: %s", normalized)
	}

	services := registry.Services{Secrets: mapResolver{"OPENAI_KEY": "sk-real"}}
	var config builtin.Config
	if err := (Registration{}).Configure(context.Background(), raw, services, &config); err != nil {
		t.Fatalf("configure with resolvable api_key: %v", err)
	}
}

// A referenced api_key the resolver cannot supply fails the driver build — at
// activation — never silently at call time.
func TestConfigureFailsClosedOnMissingAPIKeySecret(t *testing.T) {
	raw := json.RawMessage(`{"base_url":"https://api.openai.com/v1","api_key":{"secret":"OPENAI_KEY"},"capabilities":[{"operation":"chat"}]}`)
	var config builtin.Config
	// No resolver at all.
	if err := (Registration{}).Configure(context.Background(), raw, registry.Services{}, &config); err == nil {
		t.Fatal("Configure built a client referencing an api_key secret with no resolver")
	}
	// Resolver present, name unknown.
	services := registry.Services{Secrets: mapResolver{"OTHER": "x"}}
	if err := (Registration{}).Configure(context.Background(), raw, services, &config); err == nil {
		t.Fatal("Configure built a client referencing an unknown api_key secret")
	}
}
