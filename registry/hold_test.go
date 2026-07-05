package registry_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aurora-capcompute/aurora-dispatchers/builtin"
	"github.com/aurora-capcompute/aurora-dispatchers/hold"
	"github.com/aurora-capcompute/aurora-dispatchers/registry"
	"github.com/aurora-capcompute/capcompute/sys"
)

func TestHoldRegistrationConfigures(t *testing.T) {
	reg := registry.HoldRegistration{}
	if !reg.Matches("core.hold") {
		t.Fatal("should match core.hold")
	}
	if reg.Matches("inv.reserve") {
		t.Fatal("must match by type, not by operation name")
	}
	var config builtin.Config
	if err := reg.Configure(context.Background(), "inv", nil, registry.Services{}, &config); err != nil {
		t.Fatalf("configure: %v", err)
	}
	if len(config.Handlers) != 1 {
		t.Fatalf("handlers = %d, want 1", len(config.Handlers))
	}
	for _, operation := range []string{"inv.reserve", "inv.confirm", "inv.release"} {
		if !config.Handlers[0].Handles(operation) {
			t.Fatalf("handler does not handle %s", operation)
		}
	}
	if config.Handlers[0].Handles("inv") {
		t.Fatal("the bare local name is not an operation")
	}

	capabilities := make(map[string]sys.Capability, len(config.Capabilities))
	for _, capability := range config.Capabilities {
		capabilities[capability.Name] = capability
	}
	for _, want := range []string{"inv.reserve", "inv.confirm", "inv.release"} {
		capability, ok := capabilities[want]
		if !ok {
			t.Fatalf("capability %q not published: %v", want, capabilities)
		}
		if len(capability.InputSchema) == 0 {
			t.Fatalf("capability %q has no input schema", want)
		}
	}
	// The descriptions teach the TCC choreography: reserve inside a critical
	// section, register the release with sys.compensate right after, confirm
	// before sys.commit.
	reserve := capabilities["inv.reserve"].Description
	for _, teach := range []string{"sys.begin", "sys.compensate", "inv.release", "inv.confirm", "sys.commit"} {
		if !strings.Contains(reserve, teach) {
			t.Fatalf("reserve description does not teach %q: %s", teach, reserve)
		}
	}
	if confirm := capabilities["inv.confirm"].Description; !strings.Contains(confirm, "sys.commit") {
		t.Fatalf("confirm description does not anchor to sys.commit: %s", confirm)
	}
	if release := capabilities["inv.release"].Description; !strings.Contains(release, "sys.compensate") {
		t.Fatalf("release description does not name itself the sys.compensate target: %s", release)
	}
}

func TestHoldNormalizeDefaults(t *testing.T) {
	// Via Default(): core.hold is a default registration (in-memory, no
	// network credentials).
	normalized, err := registry.Default().Normalize("core.hold", nil)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	var settings registry.HoldSettings
	if err := json.Unmarshal(normalized, &settings); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if settings.DefaultTTLSeconds != int64(hold.DefaultTTL/time.Second) {
		t.Fatalf("default_ttl_seconds = %d, want %d", settings.DefaultTTLSeconds, int64(hold.DefaultTTL/time.Second))
	}
}

func TestHoldNormalizeBounds(t *testing.T) {
	for _, raw := range []string{`{"default_ttl_seconds":0}`, `{"default_ttl_seconds":-1}`, `{"default_ttl_seconds":86401}`} {
		if _, err := (registry.HoldRegistration{}).Normalize("core.hold", json.RawMessage(raw)); err == nil {
			t.Fatalf("settings %s accepted", raw)
		}
	}
	// The ceiling itself is allowed.
	if _, err := (registry.HoldRegistration{}).Normalize("core.hold", json.RawMessage(`{"default_ttl_seconds":86400}`)); err != nil {
		t.Fatalf("ceiling rejected: %v", err)
	}
}

// Settings flow into the built handler: a grant-level default TTL sets the
// pending deadline of a reserve that names none, and the default id source
// mints crypto/rand hex.
func TestHoldSettingsFlowIntoHandler(t *testing.T) {
	config, err := registry.Default().Build(context.Background(),
		[]registry.Entry{{Name: "inv", Type: "core.hold", Settings: json.RawMessage(`{"default_ttl_seconds":60}`)}},
		registry.Services{},
	)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	before := time.Now()
	result, err := config.Handlers[0].DispatchCall(context.Background(),
		sys.Syscall{Abi: sys.ABIVersion, Name: "inv.reserve", Args: json.RawMessage(`{"resource":"seat-1A"}`)},
		sys.Authorization{},
	)
	after := time.Now()
	if err != nil || result.Status() != sys.StatusResult {
		t.Fatalf("reserve = %#v, %v", result, err)
	}
	var response hold.ReserveResponse
	if err := json.Unmarshal(result.Result(), &response); err != nil {
		t.Fatalf("decode reserve: %v", err)
	}
	if response.HoldID == "" {
		t.Fatal("no hold id minted")
	}
	if _, err := hex.DecodeString(response.HoldID); err != nil {
		t.Fatalf("default hold id %q is not hex: %v", response.HoldID, err)
	}
	window := 60 * time.Second
	if response.ExpiresAtMS < before.Add(window).UnixMilli() || response.ExpiresAtMS > after.Add(window).UnixMilli() {
		t.Fatalf("expires_at_ms = %d, want now+60s from the grant settings", response.ExpiresAtMS)
	}
}
