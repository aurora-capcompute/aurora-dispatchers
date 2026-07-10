package registry_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aurora-capcompute/aurora-dispatchers/k8s"
	"github.com/aurora-capcompute/aurora-dispatchers/registry"
)

func k8sRegistry() *registry.Registry { return registry.New(registry.KubernetesRegistration{}) }

// Normalize fills defaults (version v1) and canonicalizes namespaces, while
// preserving a token as a reference (never a resolved value).
func TestKubernetesNormalizeDefaults(t *testing.T) {
	raw := json.RawMessage(`{"endpoint":"https://api.test:6443","token":{"secret":"K8S_TOKEN"},"capabilities":[{"resource":"pods","namespaces":["kube-system","default"]}]}`)
	out, err := k8sRegistry().Normalize(k8s.Capability, raw)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	var config struct {
		Token        json.RawMessage               `json:"token"`
		Capabilities []registry.KubernetesResource `json:"capabilities"`
	}
	if err := json.Unmarshal(out, &config); err != nil {
		t.Fatalf("decode normalized: %v", err)
	}
	if string(config.Token) != `{"secret":"K8S_TOKEN"}` {
		t.Fatalf("token did not round-trip as a reference: %s", config.Token)
	}
	if len(config.Capabilities) != 1 {
		t.Fatalf("capabilities = %d", len(config.Capabilities))
	}
	resource := config.Capabilities[0]
	if resource.Version != "v1" {
		t.Fatalf("version default = %q, want v1", resource.Version)
	}
	if strings.Join(resource.Namespaces, ",") != "default,kube-system" {
		t.Fatalf("namespaces not sorted/canonical: %v", resource.Namespaces)
	}
}

func TestKubernetesConfigErrors(t *testing.T) {
	cases := map[string]string{
		"no capabilities":          `{}`,
		"endpoint without token":   `{"endpoint":"https://api.test:6443","capabilities":[{"resource":"pods","namespaces":["default"]}]}`,
		"token without endpoint":   `{"token":{"secret":"T"},"capabilities":[{"resource":"pods","namespaces":["default"]}]}`,
		"http endpoint":            `{"endpoint":"http://api.test","token":"t","capabilities":[{"resource":"pods","namespaces":["default"]}]}`,
		"namespaced without ns":    `{"endpoint":"https://api.test","token":"t","capabilities":[{"resource":"pods"}]}`,
		"cluster-scoped with ns":   `{"endpoint":"https://api.test","token":"t","capabilities":[{"resource":"nodes","cluster_scoped":true,"namespaces":["default"]}]}`,
		"secrets without metadata": `{"endpoint":"https://api.test","token":"t","capabilities":[{"resource":"secrets","namespaces":["default"]}]}`,
		"duplicate resource":       `{"endpoint":"https://api.test","token":"t","capabilities":[{"resource":"pods","namespaces":["default"]},{"resource":"pods","namespaces":["default"]}]}`,
		"bad resource name":        `{"endpoint":"https://api.test","token":"t","capabilities":[{"resource":"Pods","namespaces":["default"]}]}`,
		"negative rate":            `{"endpoint":"https://api.test","token":"t","requests_per_second":-1,"capabilities":[{"resource":"pods","namespaces":["default"]}]}`,
		"unknown field":            `{"endpoint":"https://api.test","token":"t","capabilities":[{"resource":"pods","namespaces":["default"]}],"bogus":1}`,
		// list, verbs, pagination, etc. were removed: naming them is an unknown field.
		"verbs field removed":  `{"endpoint":"https://api.test","token":"t","capabilities":[{"resource":"pods","namespaces":["default"],"verbs":["list"]}]}`,
		"full_objects removed": `{"endpoint":"https://api.test","token":"t","capabilities":[{"resource":"pods","namespaces":["default"],"full_objects":true}]}`,
	}
	reg := k8sRegistry()
	for name, config := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := reg.Normalize(k8s.Capability, json.RawMessage(config)); err == nil {
				t.Fatalf("%s: accepted, want an error", name)
			}
		})
	}
}

// The "*" namespace wildcard is accepted: a get may then be authorized in any
// namespace the guest names (still one object at a time).
func TestKubernetesNamespaceWildcardAccepted(t *testing.T) {
	raw := json.RawMessage(`{"endpoint":"https://api.test","token":"t","capabilities":[{"resource":"pods","namespaces":["*"]}]}`)
	built, err := k8sRegistry().Build(context.Background(),
		[]registry.Entry{{Syscall: k8s.Capability, Config: raw}}, registry.Services{})
	if err != nil {
		t.Fatalf("wildcard namespace rejected: %v", err)
	}
	if desc := built.Capabilities[0].Description; !strings.Contains(desc, "any namespace") {
		t.Fatalf("description should note any-namespace scope: %s", desc)
	}
}

// Core Secrets are allowed only for their metadata, never their data.
func TestKubernetesSecretsMetadataOnlyAccepted(t *testing.T) {
	raw := json.RawMessage(`{"endpoint":"https://api.test","token":"t","capabilities":[{"resource":"secrets","namespaces":["default"],"metadata_only":true}]}`)
	if _, err := k8sRegistry().Normalize(k8s.Capability, raw); err != nil {
		t.Fatalf("secrets with metadata_only should be accepted: %v", err)
	}
}

// Build with an explicit endpoint+token publishes one capability named for the
// syscall, with a get-only schema and a handler that routes it — no live cluster
// required, and no list operation exists.
func TestKubernetesBuildPublishesCapability(t *testing.T) {
	config := json.RawMessage(`{"endpoint":"https://api.test:6443","token":{"secret":"K8S_TOKEN"},"capabilities":[{"resource":"pods","namespaces":["default"]},{"resource":"nodes","cluster_scoped":true}]}`)
	services := registry.Services{Secrets: mapResolver{"K8S_TOKEN": "tok-abc"}}
	built, err := k8sRegistry().Build(context.Background(),
		[]registry.Entry{{Syscall: k8s.Capability, Config: config}}, services)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(built.Capabilities) != 1 || built.Capabilities[0].Name != k8s.Capability {
		t.Fatalf("capabilities = %+v, want one named %s", built.Capabilities, k8s.Capability)
	}
	schema := string(built.Capabilities[0].InputSchema)
	if !strings.Contains(schema, `"const":"get"`) {
		t.Fatalf("schema lacks the get operation: %s", schema)
	}
	if strings.Contains(schema, `"const":"list"`) {
		t.Fatalf("schema published a list operation, which was removed: %s", schema)
	}
	if desc := built.Capabilities[0].Description; !strings.Contains(desc, "pods") || !strings.Contains(desc, "get only") {
		t.Fatalf("description missing resources or get-only note: %s", desc)
	}
	if len(built.Handlers) != 1 || !built.Handlers[0].Handles(k8s.Capability) {
		t.Fatal("handler must route by the capability name core.kubernetes")
	}
}

// A missing secret fails the build closed — the driver never activates without
// its credential.
func TestKubernetesBuildFailsClosedOnMissingSecret(t *testing.T) {
	config := json.RawMessage(`{"endpoint":"https://api.test","token":{"secret":"ABSENT"},"capabilities":[{"resource":"pods","namespaces":["default"]}]}`)
	_, err := k8sRegistry().Build(context.Background(),
		[]registry.Entry{{Syscall: k8s.Capability, Config: config}}, registry.Services{Secrets: mapResolver{}})
	if err == nil {
		t.Fatal("build succeeded with an unresolved token secret")
	}
}
