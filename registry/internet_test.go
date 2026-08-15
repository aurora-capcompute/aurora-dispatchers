package registry_test

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/aurora-capcompute/aurora-capcompute/capability"
	"github.com/aurora-capcompute/aurora-dispatchers/internet"
	"github.com/aurora-capcompute/aurora-dispatchers/registry"
	"github.com/aurora-capcompute/capcompute/sys"
)

func TestInternetMatchesSyscall(t *testing.T) {
	reg := registry.InternetRegistration{}
	if !reg.Matches("core.internet") {
		t.Fatal("should match core.internet")
	}
	if reg.Matches("core.scratch") {
		t.Fatal("must not match another syscall")
	}
}

func TestInternetNormalizeRequiresCapabilities(t *testing.T) {
	if _, err := (registry.InternetRegistration{}).Normalize("core.internet", json.RawMessage(`{}`)); err == nil {
		t.Fatal("expected error when capabilities is empty")
	}
}

// Any method the grant allowlists is accepted — the policy, not the driver,
// decides which methods are permitted.
func TestInternetNormalizeAcceptsAnyMethod(t *testing.T) {
	raw := json.RawMessage(`{"capabilities":[{"methods":["POST","delete"],"domain":"example.com"}]}`)
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
	raw := json.RawMessage(`{"capabilities":[{"methods":["GET"],"domain":"  "}]}`)
	if _, err := (registry.InternetRegistration{}).Normalize("core.internet", raw); err == nil {
		t.Fatal("expected error for empty domain")
	}
}

func TestInternetConfigurePublishesOneCapability(t *testing.T) {
	raw := json.RawMessage(`{"capabilities":[{"methods":["GET","POST"],"domain":"example.com"}]}`)
	config := capability.NewTable()
	contribution, err := (registry.InternetRegistration{}).Configure(context.Background(), raw, registry.Services{})
	if err != nil {
		t.Fatalf("configure: %v", err)
	}
	if err := config.Add(contribution); err != nil {
		t.Fatalf("add: %v", err)
	}
	if len(config.Descriptors()) != 1 || config.Descriptors()[0].Name != internet.Capability {
		t.Fatalf("capabilities = %+v, want one named %s", config.Descriptors(), internet.Capability)
	}
	if len(config.Operations(internet.Capability)) == 0 {
		t.Fatalf("handler must route by the capability name %s", internet.Capability)
	}
}

// The egress forbid floor makes a sink fail closed on omission: an internet
// grant that declared NO taints still publishes the reserved secret class as
// forbidden on every one of its methods, so a source labeled "secret" cannot
// reach egress. Enforcement is the monitor's; that it is declared at all is
// this build's job, and it is the whole of the guarantee.
func TestInternetPublishesTheEgressFloorPerMethod(t *testing.T) {
	table := capability.NewTable()
	contribution, err := (registry.InternetRegistration{}).Configure(context.Background(),
		json.RawMessage(`{"capabilities":[{"methods":["GET","POST"],"domain":"example.com"}]}`),
		registry.Services{})
	if err != nil {
		t.Fatalf("configure: %v", err)
	}
	if err := table.Add(contribution); err != nil {
		t.Fatalf("add: %v", err)
	}
	entries := table.Entries()
	if len(entries) != 2 {
		t.Fatalf("entries = %+v, want one per method (GET and POST)", entries)
	}
	for _, entry := range entries {
		if !slices.Contains(entry.Forbid, "secret") {
			t.Fatalf("SECURITY: %s forbids %v, want the reserved secret class present",
				entry.Key, entry.Forbid)
		}
	}
	// The floor is declared, not applied — an untainted run is unaffected, and
	// the index resolves a GET to exactly the entry carrying that floor.
	if got := table.Operations(internet.Capability); !slices.Contains(got, "GET") {
		t.Fatalf("operations = %v, want GET to resolve to its own entry", got)
	}
	forbid, sink := table.Forbidden(sys.Syscall{Name: internet.Capability, Args: json.RawMessage(`{"method":"GET"}`)})
	if sink != internet.Capability+"/GET" || !slices.Contains(forbid, "secret") {
		t.Fatalf("Forbidden(GET) = %v at %q, want the GET entry's floor", forbid, sink)
	}
}
