package registry_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aurora-capcompute/aurora-dispatchers/builtin"
	"github.com/aurora-capcompute/aurora-dispatchers/registry"
)

// Credential injection binds a host-held secret to a specific origin. Normalize
// rejects every unsafe shape structurally (before a secret is ever resolved);
// Configure resolves the reference host-side and fails closed on a missing one.
// The guest never supplies or sees the value — these tests pin that boundary.

func TestInjectHeadersNormalizeRejectsUnsafeShapes(t *testing.T) {
	cases := map[string]string{
		"wildcard domain": `{"capabilities":[{"methods":["GET"],"domain":"*",` +
			`"inject_headers":{"Authorization":{"secret":"ONYX_TOKEN","prefix":"Bearer "}}}]}`,
		"plain http off loopback": `{"capabilities":[{"methods":["GET"],"domain":"http://onyx.example.com",` +
			`"inject_headers":{"Authorization":{"secret":"ONYX_TOKEN"}}}]}`,
		"both sources set": `{"capabilities":[{"methods":["GET"],"domain":"onyx.example.com",` +
			`"inject_headers":{"Authorization":{"secret":"ONYX_TOKEN","value":"literal"}}}]}`,
		"no source set": `{"capabilities":[{"methods":["GET"],"domain":"onyx.example.com",` +
			`"inject_headers":{"Authorization":{"prefix":"Bearer "}}}]}`,
		"forbidden transport header": `{"capabilities":[{"methods":["GET"],"domain":"onyx.example.com",` +
			`"inject_headers":{"Host":{"secret":"ONYX_TOKEN"}}}]}`,
		"invalid header name": `{"capabilities":[{"methods":["GET"],"domain":"onyx.example.com",` +
			`"inject_headers":{"Bad Header":{"secret":"ONYX_TOKEN"}}}]}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := (registry.InternetRegistration{}).Normalize("core.internet", json.RawMessage(raw)); err == nil {
				t.Fatalf("Normalize accepted an unsafe injection (%s)", name)
			}
		})
	}
}

// A loopback origin may inject over plain http — there is no wire to sniff — and
// https is always permitted.
func TestInjectHeadersNormalizeAcceptsSafeOrigins(t *testing.T) {
	for _, domain := range []string{"onyx.example.com", "https://onyx.example.com", "http://127.0.0.1:8080", "http://localhost:9000"} {
		raw := `{"capabilities":[{"methods":["GET"],"domain":"` + domain + `",` +
			`"inject_headers":{"Authorization":{"secret":"ONYX_TOKEN","prefix":"Bearer "}}}]}`
		if _, err := (registry.InternetRegistration{}).Normalize("core.internet", json.RawMessage(raw)); err != nil {
			t.Fatalf("Normalize rejected safe origin %q: %v", domain, err)
		}
	}
}

// Normalize persists only the reference — never a resolved value — because it
// runs with no resolver and must not need one.
func TestInjectHeadersNormalizeKeepsReferenceNotValue(t *testing.T) {
	raw := `{"capabilities":[{"methods":["GET"],"domain":"onyx.example.com",` +
		`"inject_headers":{"Authorization":{"secret":"ONYX_TOKEN","prefix":"Bearer "}}}]}`
	normalized, err := (registry.InternetRegistration{}).Normalize("core.internet", json.RawMessage(raw))
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if !strings.Contains(string(normalized), `"secret":"ONYX_TOKEN"`) {
		t.Fatalf("normalized dropped the reference: %s", normalized)
	}
	if strings.Contains(string(normalized), "tok-") {
		t.Fatalf("normalized leaked a resolved value: %s", normalized)
	}
}

func TestInjectHeadersConfigureResolvesReference(t *testing.T) {
	raw := json.RawMessage(`{"capabilities":[{"methods":["GET","POST"],"domain":"https://onyx.example.com",` +
		`"inject_headers":{"Authorization":{"secret":"ONYX_TOKEN","prefix":"Bearer "}}}]}`)
	services := registry.Services{
		Secrets:  mapResolver{"ONYX_TOKEN": "tok-abc"},
		AuditKey: []byte("audit-key"),
	}
	var config builtin.Config
	if err := (registry.InternetRegistration{}).Configure(context.Background(), raw, services, &config); err != nil {
		t.Fatalf("configure: %v", err)
	}
	handler, ok := config.Handlers[0].(builtin.InternetHandler)
	if !ok {
		t.Fatalf("handler = %T, want builtin.InternetHandler", config.Handlers[0])
	}
	if len(handler.Injections) != 1 {
		t.Fatalf("injections = %+v, want one", handler.Injections)
	}
	inj := handler.Injections[0]
	if inj.Host != "onyx.example.com" {
		t.Fatalf("host = %q, want onyx.example.com", inj.Host)
	}
	if got := inj.Headers["Authorization"]; got != "Bearer tok-abc" {
		t.Fatalf("Authorization = %q, want %q", got, "Bearer tok-abc")
	}
	// The audit label names the credential and its keyed fingerprint — never the
	// token itself.
	want := "credential:ONYX_TOKEN@" + registry.CredentialFingerprint(services.AuditKey, "tok-abc")
	if len(inj.Labels) != 1 || inj.Labels[0] != want {
		t.Fatalf("labels = %v, want [%q]", inj.Labels, want)
	}
	for _, label := range inj.Labels {
		if strings.Contains(label, "tok-abc") {
			t.Fatalf("SECURITY: audit label leaked the token value: %q", label)
		}
	}
}

// A referenced secret that the resolver cannot supply fails the driver build —
// at activation, recorded — never silently at request time.
func TestInjectHeadersConfigureFailsClosedOnMissingSecret(t *testing.T) {
	raw := json.RawMessage(`{"capabilities":[{"methods":["GET"],"domain":"https://onyx.example.com",` +
		`"inject_headers":{"Authorization":{"secret":"ONYX_TOKEN","prefix":"Bearer "}}}]}`)
	var config builtin.Config
	// No resolver configured at all.
	if err := (registry.InternetRegistration{}).Configure(context.Background(), raw, registry.Services{}, &config); err == nil {
		t.Fatal("Configure built a driver referencing a secret with no resolver")
	}
	// Resolver present but the name is unknown.
	services := registry.Services{Secrets: mapResolver{"OTHER": "x"}}
	if err := (registry.InternetRegistration{}).Configure(context.Background(), raw, services, &config); err == nil {
		t.Fatal("Configure built a driver referencing an unknown secret")
	}
}
