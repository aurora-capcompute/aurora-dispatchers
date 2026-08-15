package registry_test

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/aurora-capcompute/aurora-dispatchers/builtin"
	"github.com/aurora-capcompute/aurora-dispatchers/internet"
	"github.com/aurora-capcompute/aurora-dispatchers/registry"
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
	config := builtin.NewTable()
	contribution, err := (registry.InternetRegistration{}).Configure(context.Background(), raw, registry.Services{})
	if err != nil {
		t.Fatalf("configure: %v", err)
	}
	if err := config.Add(contribution); err != nil {
		t.Fatalf("add: %v", err)
	}
	if len(config.Capabilities()) != 1 || config.Capabilities()[0].Name != internet.Capability {
		t.Fatalf("capabilities = %+v, want one named %s", config.Capabilities(), internet.Capability)
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
	table := builtin.NewTable()
	contribution, err := (registry.InternetRegistration{}).Configure(context.Background(),
		json.RawMessage(`{"capabilities":[{"methods":["GET","POST"],"domain":"example.com"}]}`),
		registry.Services{})
	if err != nil {
		t.Fatalf("configure: %v", err)
	}
	if err := table.Add(contribution); err != nil {
		t.Fatalf("add: %v", err)
	}
	published := table.Capabilities()[0]
	if len(published.Discriminator) != 1 || published.Discriminator[0] != "method" {
		t.Fatalf("discriminator = %v, want [method]", published.Discriminator)
	}
	if len(published.Operations) != 2 {
		t.Fatalf("operations = %+v, want GET and POST", published.Operations)
	}
	for _, operation := range published.Operations {
		if !slices.Contains(operation.Forbid, "secret") {
			t.Fatalf("SECURITY: %s forbids %v, want the reserved secret class present",
				operation.Name, operation.Forbid)
		}
	}
	// The floor is declared, not applied — an untainted run is unaffected.
	if _, ok := published.FindOperation(json.RawMessage(`{"method":"GET"}`)); !ok {
		t.Fatal("GET must resolve to its operation")
	}
}
