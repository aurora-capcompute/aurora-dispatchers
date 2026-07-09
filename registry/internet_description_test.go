package registry_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aurora-capcompute/aurora-dispatchers/builtin"
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
	var config builtin.Config
	if err := (registry.InternetRegistration{}).Configure(context.Background(), raw, registry.Services{}, &config); err != nil {
		t.Fatalf("configure: %v", err)
	}
	got := config.Capabilities[0].Description
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

func mustJSON(s string) string {
	out, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(out)
}
