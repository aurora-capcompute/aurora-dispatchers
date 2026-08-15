package registry_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aurora-capcompute/aurora-capcompute/capability"
	"github.com/aurora-capcompute/aurora-dispatchers/registry"
)

// An author-supplied per-origin usage note is woven into the published
// capability description — the model's tool doc — beside that origin's methods
// and domain, so a manifest can teach the model how to call the endpoint.
func TestInternetDescriptionIncludesAuthorUsageNote(t *testing.T) {
	usage := `Onyx knowledge base. Search: POST /v1/search with {"query":"..."}.`
	raw := json.RawMessage(`{"capabilities":[` +
		`{"methods":["GET","POST"],"domain":"https://onyx.example.com","description":` + mustJSON(usage) + `},` +
		`{"methods":["GET"],"domain":"https://docs.example.org"}` +
		`]}`)
	config := capability.NewTable()
	contribution, err := (registry.InternetRegistration{}).Configure(context.Background(), raw, registry.Services{})
	if err != nil {
		t.Fatalf("configure: %v", err)
	}
	if err := config.Add(contribution); err != nil {
		t.Fatalf("add: %v", err)
	}
	got := config.Capabilities()[0].Description
	for _, want := range []string{"onyx.example.com", "GET/POST", usage, "docs.example.org"} {
		if !strings.Contains(got, want) {
			t.Fatalf("description missing %q:\n%s", want, got)
		}
	}
}

// The usage note is persisted through Normalize (it is part of the policy the
// manifest carries), so the tool doc is stable across the manifest's life.
func TestInternetDescriptionRoundTripsThroughNormalize(t *testing.T) {
	usage := "Weather API; GET /v1/forecast?city=NAME."
	raw := json.RawMessage(`{"capabilities":[{"methods":["GET"],"domain":"https://api.weather.example.com","description":` + mustJSON(usage) + `}]}`)
	normalized, err := (registry.InternetRegistration{}).Normalize("core.internet", raw)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if !strings.Contains(string(normalized), usage) {
		t.Fatalf("normalized dropped the usage note: %s", normalized)
	}
}

// The note lands verbatim in the model's prompt, so it is bounded and refuses a
// control character that would corrupt that prompt. Both the over-limit case and
// a note carrying a NUL byte (valid JSON that decodes to a control byte, so this
// exercises the sanitizer rather than the parser) must be rejected at Normalize.
func TestInternetDescriptionRejectsUnsafeText(t *testing.T) {
	oversize := `{"capabilities":[{"methods":["GET"],"domain":"example.com","description":` + mustJSON(strings.Repeat("x", 2001)) + `}]}`
	withNUL := "bad" + string([]byte{0}) + "null"
	controlChar := `{"capabilities":[{"methods":["GET"],"domain":"example.com","description":` + mustJSON(withNUL) + `}]}`
	for name, bad := range map[string]string{"oversize": oversize, "control char": controlChar} {
		t.Run(name, func(t *testing.T) {
			if _, err := (registry.InternetRegistration{}).Normalize("core.internet", json.RawMessage(bad)); err == nil {
				t.Fatalf("Normalize accepted an unsafe description (%s)", name)
			}
		})
	}
}

// A credential-injecting origin is annotated automatically so the model knows
// the header is supplied for it and must not be set by the guest — naming the
// header, never the secret.
func TestInternetDescriptionAnnotatesInjectedHeaders(t *testing.T) {
	raw := json.RawMessage(`{"capabilities":[{"methods":["GET","POST"],"domain":"https://onyx.example.com",` +
		`"description":"Onyx KB.","inject_headers":{"Authorization":{"secret":"ONYX_TOKEN","prefix":"Bearer "}}}]}`)
	config := capability.NewTable()
	services := registry.Services{Secrets: mapResolver{"ONYX_TOKEN": "tok-abc"}, AuditKey: []byte("k")}
	contribution, err := (registry.InternetRegistration{}).Configure(context.Background(), raw, services)
	if err != nil {
		t.Fatalf("configure: %v", err)
	}
	if err := config.Add(contribution); err != nil {
		t.Fatalf("add: %v", err)
	}
	got := config.Capabilities()[0].Description
	for _, want := range []string{"Onyx KB.", "Authorization", "attached automatically", "do not set it"} {
		if !strings.Contains(got, want) {
			t.Fatalf("description missing %q:\n%s", want, got)
		}
	}
	// The note must never reveal the secret reference or its value.
	for _, leak := range []string{"ONYX_TOKEN", "tok-abc"} {
		if strings.Contains(got, leak) {
			t.Fatalf("SECURITY: description leaked %q:\n%s", leak, got)
		}
	}
}

// Multiple injected headers are listed together and pluralized.
func TestInternetDescriptionAnnotatesMultipleInjectedHeaders(t *testing.T) {
	raw := json.RawMessage(`{"capabilities":[{"methods":["GET"],"domain":"https://onyx.example.com",` +
		`"inject_headers":{"Authorization":{"secret":"ONYX_TOKEN"},"X-Api-Key":{"secret":"ONYX_KEY"}}}]}`)
	config := capability.NewTable()
	services := registry.Services{Secrets: mapResolver{"ONYX_TOKEN": "t", "ONYX_KEY": "k"}}
	contribution, err := (registry.InternetRegistration{}).Configure(context.Background(), raw, services)
	if err != nil {
		t.Fatalf("configure: %v", err)
	}
	if err := config.Add(contribution); err != nil {
		t.Fatalf("add: %v", err)
	}
	got := config.Capabilities()[0].Description
	for _, want := range []string{"Authorization, X-Api-Key", "do not set them"} {
		if !strings.Contains(got, want) {
			t.Fatalf("description missing %q:\n%s", want, got)
		}
	}
}

func mustJSON(s string) string {
	out, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(out)
}
