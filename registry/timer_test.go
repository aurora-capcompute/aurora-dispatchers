package registry_test

import (
	"context"
	"encoding/json"
	"testing"

	"aurora-dispatchers/builtin"
	"aurora-dispatchers/registry"
)

func TestTimerRegistrationConfigures(t *testing.T) {
	reg := registry.TimerRegistration{}
	if !reg.Matches("timer.set") {
		t.Fatal("should match timer.set")
	}
	var config builtin.Config
	if err := reg.Configure(context.Background(), "timer.set", nil, registry.Services{}, &config); err != nil {
		t.Fatalf("configure: %v", err)
	}
	if len(config.Handlers) != 1 {
		t.Fatalf("handlers = %d, want 1", len(config.Handlers))
	}
	if !config.Handlers[0].Handles("timer.set") {
		t.Fatal("handler does not handle timer.set")
	}
	if len(config.Capabilities) != 1 || config.Capabilities[0].Name != "timer.set" {
		t.Fatalf("capabilities = %+v", config.Capabilities)
	}
}

func TestTimerNormalizeDefaults(t *testing.T) {
	normalized, err := registry.TimerRegistration{}.Normalize("timer.set", nil)
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
	_, err := registry.TimerRegistration{}.Normalize("timer.set", json.RawMessage(`{"max_duration_ms":0}`))
	if err == nil {
		t.Fatal("expected error for zero max_duration_ms")
	}
}
