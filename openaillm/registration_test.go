package openaillm

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/aurora-capcompute/aurora-capcompute/capability"
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
	config := capability.NewTable()
	contribution, err := (Registration{}).Configure(context.Background(), raw, registry.Services{})
	if err != nil {
		t.Fatalf("configure: %v", err)
	}
	if err := config.Add(contribution); err != nil {
		t.Fatalf("add: %v", err)
	}
	if len(config.Descriptors()) != 1 || config.Descriptors()[0].Name != SyscallType {
		t.Fatalf("capabilities = %+v, want one named %s", config.Descriptors(), SyscallType)
	}
	schema := string(config.Descriptors()[0].InputSchema)
	if !strings.Contains(schema, `"oneOf"`) || !strings.Contains(schema, `"chat"`) || !strings.Contains(schema, `"models"`) {
		t.Fatalf("input schema is not a oneOf over the granted operations: %s", schema)
	}
	if len(config.Operations(SyscallType)) == 0 {
		t.Fatalf("handler must route by the capability name %s", SyscallType)
	}
}

func TestConfigureRequiresOperations(t *testing.T) {
	raw := json.RawMessage(`{"base_url":"https://api.openai.com/v1","api_key":"sk-test"}`)
	if _, err := (Registration{}).Configure(context.Background(), raw, registry.Services{}); err == nil {
		t.Fatal("expected error when no operations are granted")
	}
	bad := json.RawMessage(`{"api_key":"sk-test","capabilities":[{"operation":"nope"}]}`)
	if _, err := (Registration{}).Configure(context.Background(), bad, registry.Services{}); err == nil {
		t.Fatal("expected error for an unknown operation")
	}
}

// mapResolver is a test SecretResolver backed by a map.
type mapResolver map[string]string

func (m mapResolver) Resolve(name string) (string, bool) { v, ok := m[name]; return v, ok }

// The api_key may be a host-held reference resolved at activation. The manifest
// keeps only the reference: validation refuses or accepts and rewrites nothing,
// so there is no path by which a resolved secret could be written back into the
// stored grant. Configure resolves it in memory for the client it builds, and
// that client is all that ever holds the value.
func TestConfigureResolvesAPIKeyReference(t *testing.T) {
	raw := json.RawMessage(`{"base_url":"https://api.openai.com/v1","api_key":{"secret":"OPENAI_KEY"},"capabilities":[{"operation":"chat"}]}`)

	// Validating the grant needs the resolver — a reference to a secret this
	// deployment does not hold is refused at the door rather than at spawn.
	resolver := registry.Services{Secrets: mapResolver{"OPENAI_KEY": "sk-real"}}
	if err := registry.New(Registration{}).ValidateConfig(context.Background(), SyscallType, raw, resolver); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if err := registry.New(Registration{}).ValidateConfig(context.Background(), SyscallType, raw, registry.Services{}); err == nil {
		t.Fatal("a grant referencing a secret the deployment does not hold was admitted")
	}
	if strings.Contains(string(raw), "sk-real") {
		t.Fatalf("SECURITY: validation wrote a resolved secret back into the grant: %s", raw)
	}

	services := registry.Services{Secrets: mapResolver{"OPENAI_KEY": "sk-real"}}
	if _, err := (Registration{}).Configure(context.Background(), raw, services); err != nil {
		t.Fatalf("configure with resolvable api_key: %v", err)
	}
}

// A referenced api_key the resolver cannot supply fails the driver build — at
// activation — never silently at call time.
func TestConfigureFailsClosedOnMissingAPIKeySecret(t *testing.T) {
	raw := json.RawMessage(`{"base_url":"https://api.openai.com/v1","api_key":{"secret":"OPENAI_KEY"},"capabilities":[{"operation":"chat"}]}`)
	// No resolver at all.
	if _, err := (Registration{}).Configure(context.Background(), raw, registry.Services{}); err == nil {
		t.Fatal("Configure built a client referencing an api_key secret with no resolver")
	}
	// Resolver present, name unknown.
	services := registry.Services{Secrets: mapResolver{"OTHER": "x"}}
	if _, err := (Registration{}).Configure(context.Background(), raw, services); err == nil {
		t.Fatal("Configure built a client referencing an unknown api_key secret")
	}
}

// What this driver owes the flow monitor is the declaration, not the
// enforcement: each operation's own source classes, and the reserved egress
// floor on its sink guard because a provider call sends the prompt off-host.
// Before this moved onto the entries, openai's sink guard ran inside the handler
// — below the replay tape, so a taint denial was journaled as a completion and
// replayed forever instead of re-deriving from the run's current taint.
func TestConfigurePublishesFlowPolicyPerOperation(t *testing.T) {
	raw := json.RawMessage(`{"base_url":"https://api.example.com","api_key":"k",` +
		`"capabilities":[{"operation":"chat","labels":["ai_output"],"taints":["untrusted_web"]}]}`)
	family, err := Registration{}.Configure(context.Background(), raw, registry.Services{})
	if err != nil {
		t.Fatalf("configure: %v", err)
	}
	table := capability.NewTable()
	if err := table.Add(family); err != nil {
		t.Fatalf("add: %v", err)
	}
	entries := table.Entries()
	if len(entries) != 1 {
		t.Fatalf("entries = %+v, want one per granted operation", entries)
	}
	if !slices.Contains(entries[0].Labels, "ai_output") {
		t.Fatalf("labels = %v, want the operation's declared source class", entries[0].Labels)
	}
	for _, want := range []string{"untrusted_web", "secret"} {
		if !slices.Contains(entries[0].Forbid, want) {
			t.Fatalf("SECURITY: forbid = %v, want %q (declared taint plus the egress floor)",
				entries[0].Forbid, want)
		}
	}
}
