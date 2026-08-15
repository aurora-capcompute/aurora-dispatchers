package registry_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aurora-capcompute/aurora-dispatchers/builtin"
	"github.com/aurora-capcompute/aurora-dispatchers/httptemplate"
	"github.com/aurora-capcompute/aurora-dispatchers/registry"
)

func TestTemplateMatches(t *testing.T) {
	reg := registry.HTTPTemplateRegistration{}
	if !reg.Matches("core.httpTemplate") {
		t.Fatal("should match core.httpTemplate")
	}
	if reg.Matches("core.internet") {
		t.Fatal("must not match another syscall")
	}
}

func TestTemplateNormalizeRejectsBadConfigs(t *testing.T) {
	cases := map[string]string{
		"no operations":            `{"base_url":"https://onyx.example.com","capabilities":[]}`,
		"plain http origin":        `{"base_url":"http://onyx.example.com","capabilities":[{"operation":"s","method":"GET","path":"/s"}]}`,
		"wildcard method":          `{"base_url":"https://onyx.example.com","capabilities":[{"operation":"s","method":"*","path":"/s"}]}`,
		"relative path":            `{"base_url":"https://onyx.example.com","capabilities":[{"operation":"s","method":"GET","path":"s"}]}`,
		"bad param type":           `{"base_url":"https://onyx.example.com","capabilities":[{"operation":"s","method":"GET","path":"/s","params":{"q":{"type":"blob"}}}]}`,
		"placeholder no param":     `{"base_url":"https://onyx.example.com","capabilities":[{"operation":"s","method":"POST","path":"/s","body":{"m":"{{q}}"}}]}`,
		"duplicate operation":      `{"base_url":"https://onyx.example.com","capabilities":[{"operation":"s","method":"GET","path":"/a"},{"operation":"s","method":"GET","path":"/b"}]}`,
		"grant-level inject gone":  `{"base_url":"https://onyx.example.com","inject_headers":{"Authorization":{"secret":"X"}},"capabilities":[{"operation":"s","method":"GET","path":"/s"}]}`,
		"op injects forbidden hdr": `{"capabilities":[{"operation":"s","method":"GET","base_url":"https://onyx.example.com","path":"/s","inject_headers":{"Host":{"secret":"X"}}}]}`,
		"op missing base_url":      `{"capabilities":[{"operation":"s","method":"GET","path":"/s"}]}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := (registry.HTTPTemplateRegistration{}).Normalize("core.httpTemplate", json.RawMessage(raw)); err == nil {
				t.Fatalf("Normalize accepted an invalid config (%s)", name)
			}
		})
	}
}

// A loopback origin may use plain http (no wire to sniff), and a valid grant
// normalizes cleanly.
func TestTemplateNormalizeAcceptsValid(t *testing.T) {
	for _, base := range []string{"https://onyx.example.com", "http://127.0.0.1:8080"} {
		raw := `{"base_url":"` + base + `","capabilities":[{"operation":"search","method":"POST","path":"/s","body":{"m":"{{q}}"},"params":{"q":{"type":"string","required":true}}}]}`
		if _, err := (registry.HTTPTemplateRegistration{}).Normalize("core.httpTemplate", json.RawMessage(raw)); err != nil {
			t.Fatalf("Normalize rejected a valid grant on %q: %v", base, err)
		}
	}
}

func templateConfigJSON() string {
	return `{"capabilities":[{"operation":"search","description":"Search the KB.","method":"POST",` +
		`"base_url":"https://onyx.example.com","path":"/api/search",` +
		`"inject_headers":{"Authorization":{"secret":"ONYX_TOKEN","prefix":"Bearer "}},` +
		`"body":{"message":"{{query}}","persona_id":0},"params":{"query":{"type":"string","required":true,"description":"the question"}}}]}`
}

// Configure publishes one capability named for the syscall, a oneOf over the
// operations, and a handler that routes it.
func TestTemplateConfigurePublishesCapability(t *testing.T) {
	services := registry.Services{Secrets: mapResolver{"ONYX_TOKEN": "tok-abc"}, AuditKey: []byte("k")}
	config := builtin.NewTable()
	contribution, err := (registry.HTTPTemplateRegistration{}).Configure(
		context.Background(), json.RawMessage(templateConfigJSON()), services)
	if err != nil {
		t.Fatalf("configure: %v", err)
	}
	if err := config.Add(contribution); err != nil {
		t.Fatalf("add: %v", err)
	}
	if len(config.Capabilities()) != 1 || config.Capabilities()[0].Name != "core.httpTemplate" {
		t.Fatalf("capabilities = %+v, want one named core.httpTemplate", config.Capabilities())
	}
	schema := string(config.Capabilities()[0].InputSchema)
	for _, want := range []string{`"oneOf"`, `"search"`, `"query"`} {
		if !strings.Contains(schema, want) {
			t.Fatalf("schema missing %q: %s", want, schema)
		}
	}
	desc := config.Capabilities()[0].Description
	if !strings.Contains(desc, "search") || !strings.Contains(desc, "Search the KB.") {
		t.Fatalf("description does not document the operation: %s", desc)
	}
	if len(config.Operations("core.httpTemplate")) == 0 {
		t.Fatalf("handler must route core.httpTemplate")
	}
	// The resolved token must never appear in the published surface.
	if strings.Contains(schema, "tok-abc") || strings.Contains(desc, "tok-abc") {
		t.Fatal("SECURITY: the resolved credential leaked into the published capability")
	}
}

// One grant may front several APIs: operations targeting different hosts, each
// with its own credential, unioned into one ADT capability. Each operation's
// credential is bound to its own host and must not bleed to the other.
func TestTemplateConfigureSpansMultipleHosts(t *testing.T) {
	raw := `{"capabilities":[` +
		`{"operation":"search","method":"POST","base_url":"https://onyx.example.com","path":"/api/search",` +
		`"inject_headers":{"Authorization":{"secret":"ONYX_TOKEN","prefix":"Bearer "}},` +
		`"body":{"q":"{{query}}"},"params":{"query":{"type":"string","required":true}}},` +
		`{"operation":"weather","method":"GET","base_url":"https://api.weather.example.com","path":"/v1/now",` +
		`"inject_headers":{"X-Api-Key":{"secret":"WEATHER_KEY"}}}` +
		`]}`
	services := registry.Services{Secrets: mapResolver{"ONYX_TOKEN": "tok-abc", "WEATHER_KEY": "wk-xyz"}}
	config := builtin.NewTable()
	contribution, err := (registry.HTTPTemplateRegistration{}).Configure(
		context.Background(), json.RawMessage(raw), services)
	if err != nil {
		t.Fatalf("configure: %v", err)
	}
	if err := config.Add(contribution); err != nil {
		t.Fatalf("add: %v", err)
	}
	handler, ok := config.Entries()[0].Handler.(httptemplate.Handler)
	if !ok {
		t.Fatalf("handler = %T, want httptemplate.Handler", config.Entries()[0].Handler)
	}
	search, weather := handler.Operations["search"], handler.Operations["weather"]
	if search.BaseURL != "https://onyx.example.com" || weather.BaseURL != "https://api.weather.example.com" {
		t.Fatalf("operations did not keep their own origins: %q, %q", search.BaseURL, weather.BaseURL)
	}
	// Each operation carries only its own credential — no bleed across hosts.
	if search.Headers["Authorization"] != "Bearer tok-abc" || len(search.Headers) != 1 {
		t.Fatalf("search headers = %v, want only its Authorization", search.Headers)
	}
	if weather.Headers["X-Api-Key"] != "wk-xyz" || len(weather.Headers) != 1 {
		t.Fatalf("weather headers = %v, want only its X-Api-Key", weather.Headers)
	}
	if _, leaked := weather.Headers["Authorization"]; leaked {
		t.Fatal("SECURITY: the Onyx token bled into the weather operation")
	}
}

// A referenced secret the resolver cannot supply fails the driver build — at
// activation — never at request time.
func TestTemplateConfigureFailsClosedOnMissingSecret(t *testing.T) {
	if _, err := (registry.HTTPTemplateRegistration{}).Configure(context.Background(), json.RawMessage(templateConfigJSON()), registry.Services{}); err == nil {
		t.Fatal("Configure built a handler referencing a secret with no resolver")
	}
	services := registry.Services{Secrets: mapResolver{"OTHER": "x"}}
	if _, err := (registry.HTTPTemplateRegistration{}).Configure(context.Background(), json.RawMessage(templateConfigJSON()), services); err == nil {
		t.Fatal("Configure built a handler referencing an unknown secret")
	}
}

// Normalize persists only the credential reference, never a resolved value.
func TestTemplateNormalizeKeepsSecretReference(t *testing.T) {
	normalized, err := (registry.HTTPTemplateRegistration{}).Normalize("core.httpTemplate", json.RawMessage(templateConfigJSON()))
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if !strings.Contains(string(normalized), `"secret":"ONYX_TOKEN"`) {
		t.Fatalf("normalized dropped the reference: %s", normalized)
	}
	if strings.Contains(string(normalized), "tok-abc") {
		t.Fatalf("normalized leaked a resolved value: %s", normalized)
	}
}
