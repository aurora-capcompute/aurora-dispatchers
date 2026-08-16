package registry_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aurora-capcompute/aurora-capcompute/capability"

	"github.com/aurora-capcompute/aurora-dispatchers/registry"
)

// A manifest must not be able to declare a label in the kernel's reserved
// "syscall:" provenance namespace: that provenance is the kernel's to stamp
// (the Labeler), never a grant's to claim, or a manifest could forge the
// origin of its own data and launder tainted values as trusted. The guard is
// capability.NormalizeLabels, reached through FlowPolicy.Normalized.
func TestFlowPolicyRejectsReservedLabelNamespace(t *testing.T) {
	forged := capability.SyscallLabelPrefix + "internet.read"

	t.Run("as a source label", func(t *testing.T) {
		_, err := registry.FlowPolicy{Labels: []string{forged}}.Normalized()
		if err == nil || !strings.Contains(err.Error(), capability.SyscallLabelPrefix) {
			t.Fatalf("err = %v, want a reserved-prefix rejection", err)
		}
	})

	t.Run("as a sink taint", func(t *testing.T) {
		_, err := registry.FlowPolicy{Taints: []string{forged}}.Normalized()
		if err == nil || !strings.Contains(err.Error(), capability.SyscallLabelPrefix) {
			t.Fatalf("err = %v, want a reserved-prefix rejection", err)
		}
	})

	t.Run("canonicalizes an honest policy", func(t *testing.T) {
		got, err := registry.FlowPolicy{
			Labels: []string{"  stored ", "stored", "b", "a"},
			Taints: []string{"untrusted_web"},
		}.Normalized()
		if err != nil {
			t.Fatalf("normalize: %v", err)
		}
		if strings.Join(got.Labels, ",") != "a,b,stored" {
			t.Fatalf("labels = %v, want trimmed/dedup/sorted", got.Labels)
		}
	})
}

// The same guard must hold through a real driver registration's manifest-time
// Normalize — not only the helper — so a forged label in a leaf grant's
// `capabilities` list is refused when the manifest is validated, before any
// process runs.
func TestDriverManifestRejectsForgedProvenanceLabel(t *testing.T) {
	forged := `{"capabilities":[{"operation":"put","labels":["` + capability.SyscallLabelPrefix + `internet.read"]}]}`
	if err := registry.New(registry.InternetRegistration{}, registry.ScratchRegistration{}).ValidateConfig(context.Background(), "core.scratch", json.RawMessage(forged), registry.Services{}); err == nil {
		t.Fatal("core.memory manifest declaring a reserved syscall: label was accepted; want rejection at manifest time")
	}

	// The identical grant with an honest label normalizes cleanly, proving the
	// rejection above is specific to the reserved namespace, not a blanket refusal.
	honest := `{"capabilities":[{"operation":"put","labels":["stored"]}]}`
	if err := registry.New(registry.InternetRegistration{}, registry.ScratchRegistration{}).ValidateConfig(context.Background(), "core.scratch", json.RawMessage(honest), registry.Services{}); err != nil {
		t.Fatalf("honest core.memory manifest rejected: %v", err)
	}
}
