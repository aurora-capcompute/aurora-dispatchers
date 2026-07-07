package registry_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aurora-capcompute/aurora-dispatchers/builtin"
	"github.com/aurora-capcompute/aurora-dispatchers/internet"
	"github.com/aurora-capcompute/aurora-dispatchers/registry"
)

func TestInternetMatchesType(t *testing.T) {
	reg := registry.InternetRegistration{}
	if !reg.Matches("core.internet") {
		t.Fatal("should match core.internet")
	}
	if reg.Matches(internet.Capability) {
		t.Fatal("must match by type, not the capability name")
	}
}

func TestInternetNormalizeRequiresPermissions(t *testing.T) {
	if _, err := (registry.InternetRegistration{}).Normalize("core.internet", json.RawMessage(`{}`)); err == nil {
		t.Fatal("expected error when permissions is empty")
	}
}

// Any method the grant allowlists is accepted — the policy, not the driver,
// decides which methods are permitted.
func TestInternetNormalizeAcceptsAnyMethod(t *testing.T) {
	raw := json.RawMessage(`{"permissions":[{"methods":["POST","delete"],"domain":"example.com"}]}`)
	normalized, err := (registry.InternetRegistration{}).Normalize("core.internet", raw)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	// Methods are canonicalized (uppercased) in the normalized form.
	if !strings.Contains(string(normalized), `"POST"`) || !strings.Contains(string(normalized), `"DELETE"`) {
		t.Fatalf("normalized = %s, want uppercased methods", normalized)
	}
}

func TestInternetNormalizeRejectsEmptyDomain(t *testing.T) {
	raw := json.RawMessage(`{"permissions":[{"methods":["GET"],"domain":"  "}]}`)
	if _, err := (registry.InternetRegistration{}).Normalize("core.internet", raw); err == nil {
		t.Fatal("expected error for empty domain")
	}
}

func TestInternetConfigurePublishesCanonicalName(t *testing.T) {
	raw := json.RawMessage(`{"permissions":[{"methods":["GET","POST"],"domain":"example.com"}]}`)
	var config builtin.Config
	if err := (registry.InternetRegistration{}).Configure(context.Background(), raw, registry.Services{}, &config); err != nil {
		t.Fatalf("configure: %v", err)
	}
	if len(config.Capabilities) != 1 || config.Capabilities[0].Name != internet.Capability {
		t.Fatalf("capabilities = %+v, want one named %s", config.Capabilities, internet.Capability)
	}
	if len(config.Handlers) != 1 || !config.Handlers[0].Handles(internet.Capability) {
		t.Fatalf("handler must route by the canonical name %s", internet.Capability)
	}
}
