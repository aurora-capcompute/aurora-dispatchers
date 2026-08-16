package scratch_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aurora-capcompute/aurora-capcompute/capability"
	"github.com/aurora-capcompute/aurora-dispatchers/registry"
)

// registryValidate is the door check: it builds what the spawn would build and
// throws it away, so a test asserting a refusal asserts what CreateProcess does.
func registryValidate(r registry.Registration, syscall string, config json.RawMessage) (json.RawMessage, error) {
	err := registry.New(r).ValidateConfig(context.Background(), syscall, config,
		registry.Services{Secrets: anySecret{}})
	return config, err
}

type anySecret struct{}

func (anySecret) Resolve(name string) (string, bool) { return "resolved-" + name, true }

// assertMenuOffers checks the published schema offers every operation the table
// routes. Whether that schema is a union is capability.Table's business, pinned
// there.
func assertMenuOffers(t *testing.T, table *capability.Table, syscall string) {
	t.Helper()
	descriptor, served := table.Descriptor(syscall)
	if !served {
		t.Fatalf("%s is not served", syscall)
	}
	for _, operation := range table.Operations(syscall) {
		if !strings.Contains(string(descriptor.InputSchema), `"const":"`+operation+`"`) {
			t.Fatalf("menu does not offer the granted operation %q: %s", operation, descriptor.InputSchema)
		}
	}
}
