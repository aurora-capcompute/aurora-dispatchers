package registry_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/aurora-capcompute/aurora-dispatchers/builtin"
	"github.com/aurora-capcompute/aurora-dispatchers/registry"
)

func TestInternetMatchesType(t *testing.T) {
	reg := registry.InternetRegistration{}
	if !reg.Matches("core.internet") {
		t.Fatal("should match core.internet")
	}
	if reg.Matches("internet.read") {
		t.Fatal("must match by type, not the old capability name")
	}
}

func TestInternetNormalizeRequiresPermissions(t *testing.T) {
	if _, err := (registry.InternetRegistration{}).Normalize("core.internet", json.RawMessage(`{}`)); err == nil {
		t.Fatal("expected error when permissions is empty")
	}
}

func TestInternetNormalizeRejectsNonGET(t *testing.T) {
	raw := json.RawMessage(`{"permissions":[{"requestType":"POST","domain":"example.com"}]}`)
	if _, err := (registry.InternetRegistration{}).Normalize("core.internet", raw); err == nil {
		t.Fatal("expected error for non-GET request type")
	}
}

func TestInternetConfigurePublishesUnderLocalName(t *testing.T) {
	raw := json.RawMessage(`{"permissions":[{"requestType":"GET","domain":"example.com"}]}`)
	var config builtin.Config
	if err := (registry.InternetRegistration{}).Configure(context.Background(), "internetAccess", raw, registry.Services{}, &config); err != nil {
		t.Fatalf("configure: %v", err)
	}
	if len(config.Capabilities) != 1 || config.Capabilities[0].Name != "internetAccess" {
		t.Fatalf("capabilities = %+v, want one named internetAccess", config.Capabilities)
	}
	if len(config.Handlers) != 1 || !config.Handlers[0].Handles("internetAccess") {
		t.Fatal("handler must route by the local name internetAccess")
	}
}
