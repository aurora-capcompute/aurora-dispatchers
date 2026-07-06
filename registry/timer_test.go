package registry_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/aurora-capcompute/aurora-dispatchers/builtin"
	"github.com/aurora-capcompute/aurora-dispatchers/registry"
	"github.com/aurora-capcompute/aurora-dispatchers/timer"
)

func TestTimerRegistrationConfigures(t *testing.T) {
	reg := registry.TimerRegistration{}
	if !reg.Matches("core.timer") {
		t.Fatal("should match core.timer")
	}
	if reg.Matches("timer.set") {
		t.Fatal("must match by the granted syscall, not the capability name")
	}
	var config builtin.Config
	if err := reg.Configure(context.Background(), nil, registry.Services{}, &config); err != nil {
		t.Fatalf("configure: %v", err)
	}
	if len(config.Handlers) != 1 {
		t.Fatalf("handlers = %d, want 1", len(config.Handlers))
	}
	if !config.Handlers[0].Handles(timer.Capability) {
		t.Fatalf("handler does not handle the canonical name %s", timer.Capability)
	}
	if len(config.Capabilities) != 1 || config.Capabilities[0].Name != timer.Capability {
		t.Fatalf("capabilities = %+v", config.Capabilities)
	}
}

func TestTimerNormalizeDefaults(t *testing.T) {
	normalized, err := registry.TimerRegistration{}.Normalize("core.timer", nil)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	var settings registry.TimerSettings
	if err := json.Unmarshal(normalized, &settings); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if settings.MaxDurationMS <= 0 {
		t.Fatalf("max_duration_ms = %d, want positive default", settings.MaxDurationMS)
	}
}

func TestTimerNormalizeRejectsNonPositiveMax(t *testing.T) {
	_, err := registry.TimerRegistration{}.Normalize("core.timer", json.RawMessage(`{"max_duration_ms":0}`))
	if err == nil {
		t.Fatal("expected error for zero max_duration_ms")
	}
}
