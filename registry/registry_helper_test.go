package registry_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aurora-capcompute/aurora-capcompute/capability"
	"github.com/aurora-capcompute/aurora-dispatchers/registry"
)

// registryValidate is the door check one registration at a time: it builds what
// the spawn would build and throws it away, so a test asserting a refusal is
// asserting exactly what CreateProcess asserts.
func registryValidate(r registry.Registration, syscall string, config json.RawMessage) (json.RawMessage, error) {
	// A permissive resolver: validation builds what the spawn would build, so a
	// grant referencing a host-held secret needs one. Tests about refusals still
	// refuse on their own grounds; this only keeps a missing secret from standing
	// in for the failure they mean to assert.
	services := registry.Services{Secrets: anySecret{}}
	err := registry.New(r).ValidateConfig(context.Background(), syscall, config, services)
	return config, err
}

// assertMenuIsTheGrant checks the published schema is a projection of the cases
// the table actually routes: every granted operation is pinned in it as a
// constant, and a grant with more than one case is a union over them — while one
// case is that case's own shape, since a oneOf of one branch says nothing more.
//
// It applies to grants whose cases pin their own discriminator (the drivers
// built on OperationBranch). core.internet does not: its methods share one flat
// shape and are told apart by the index alone, which is why its menu is that
// shape rather than a union of copies of it.
func assertMenuIsTheGrant(t *testing.T, table *capability.Table, syscall string) {
	t.Helper()
	descriptor, served := table.Descriptor(syscall)
	if !served {
		t.Fatalf("%s is not served", syscall)
	}
	schema := string(descriptor.InputSchema)
	operations := table.Operations(syscall)
	for _, operation := range operations {
		if !strings.Contains(schema, `"const":"`+operation+`"`) {
			t.Fatalf("menu does not offer the granted operation %q: %s", operation, schema)
		}
	}
	if union := strings.Contains(schema, `"oneOf"`); union != (len(operations) > 1) {
		t.Fatalf("menu for %d operations %v is a union: %v — %s", len(operations), operations, union, schema)
	}
}

type anySecret struct{}

func (anySecret) Resolve(name string) (string, bool) { return "resolved-" + name, true }
