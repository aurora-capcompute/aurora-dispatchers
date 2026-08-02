package registry_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aurora-capcompute/aurora-dispatchers/builtin"
	"github.com/aurora-capcompute/aurora-dispatchers/command"
	"github.com/aurora-capcompute/aurora-dispatchers/registry"
)

// kubectlGrant is the shape this driver exists for: a host-owned script, a
// closed set of contexts, and a pattern for the resource.
const kubectlGrant = `{"capabilities":[{"operation":"run","commands":[{
  "name":"kubectl-get",
  "description":"List Kubernetes objects in a cluster",
  "path":"/bin/bash",
  "args":["/opt/aurora/bin/kubectl-get.sh","{context}","{resource}","{namespace}"],
  "env":{"KUBECONFIG":"/etc/aurora/kubeconfig","PATH":"/usr/bin:/bin"},
  "params":{
    "context":["prod-eu","staging"],
    "resource":"[a-z][a-z0-9]*",
    "namespace":"[a-z0-9]([a-z0-9-]*[a-z0-9])?"
  },
  "timeout_ms":10000,
  "require_approval":false,
  "labels":["k8s"]
}]}]}`

func configure(t *testing.T, grant string) builtin.Config {
	t.Helper()
	var out builtin.Config
	if err := (registry.CommandRegistration{}).Configure(context.Background(), json.RawMessage(grant), registry.Services{}, &out); err != nil {
		t.Fatalf("configure: %v", err)
	}
	return out
}

// The published schema is the first enforcement point: the kernel Validator
// checks it before the driver runs, so the closed set of contexts is enforced
// twice — and the model can see which contexts exist.
func TestPublishedSchemaCarriesTheClosedSet(t *testing.T) {
	out := configure(t, kubectlGrant)
	if len(out.Capabilities) != 1 || out.Capabilities[0].Name != command.Capability {
		t.Fatalf("capabilities = %+v", out.Capabilities)
	}
	schema := string(out.Capabilities[0].InputSchema)
	for _, want := range []string{`"prod-eu"`, `"staging"`, `"kubectl-get"`, `"enum"`} {
		if !strings.Contains(schema, want) {
			t.Fatalf("schema does not carry %s:\n%s", want, schema)
		}
	}
	if strings.Contains(schema, "dev") {
		t.Fatalf("schema admits an ungranted context:\n%s", schema)
	}
	// The description tells the model what it may choose.
	if desc := out.Capabilities[0].Description; !strings.Contains(desc, "prod-eu") || !strings.Contains(desc, "staging") {
		t.Fatalf("description does not list the contexts: %s", desc)
	}
}

// An author's pattern is anchored by the loader, so an unanchored one cannot
// admit more than it appears to.
func TestPatternsAreAnchored(t *testing.T) {
	grant := `{"capabilities":[{"operation":"run","commands":[{
	  "name":"echo","path":"/bin/echo","args":["{env}"],
	  "params":{"env":"prod"}}]}]}`
	out := configure(t, grant)
	handler, ok := out.Handlers[0].(command.Handler)
	if !ok {
		t.Fatalf("handler = %T", out.Handlers[0])
	}
	param := handler.Commands[0].Params["env"]
	if param.Pattern == nil {
		t.Fatal("pattern was not compiled")
	}
	if param.Pattern.MatchString("not-prod-really") {
		t.Fatal("an unanchored pattern was left unanchored: it admits more than it says")
	}
	if !param.Pattern.MatchString("prod") {
		t.Fatal("the anchored pattern must still admit its own value")
	}
}

// Approval defaults on. This driver runs host commands: an author who wants it
// unattended says so explicitly.
func TestApprovalDefaultsOn(t *testing.T) {
	grant := `{"capabilities":[{"operation":"run","commands":[{"name":"echo","path":"/bin/echo"}]}]}`
	out := configure(t, grant)
	handler := out.Handlers[0].(command.Handler)
	if !handler.Commands[0].RequireApproval {
		t.Fatal("require_approval must default to true for core.command")
	}
}

// Configuration that would be unsafe or incoherent is refused where it is
// written, not where it runs.
func TestCommandConfigErrors(t *testing.T) {
	cases := []struct {
		name  string
		grant string
		want  string
	}{
		{"no capabilities", `{}`, "at least one operation"},
		{"unknown operation", `{"capabilities":[{"operation":"exec","commands":[{"name":"a","path":"/bin/echo"}]}]}`, "run-only"},
		{"relative path", `{"capabilities":[{"operation":"run","commands":[{"name":"a","path":"echo"}]}]}`, "absolute"},
		{"uncleaned path", `{"capabilities":[{"operation":"run","commands":[{"name":"a","path":"/usr/bin/../bin/echo"}]}]}`, "cleaned"},
		{"relative dir", `{"capabilities":[{"operation":"run","commands":[{"name":"a","path":"/bin/echo","dir":"work"}]}]}`, "absolute"},
		{"undeclared placeholder", `{"capabilities":[{"operation":"run","commands":[{"name":"a","path":"/bin/echo","args":["{ctx}"]}]}]}`, "undeclared parameter"},
		{"unused parameter", `{"capabilities":[{"operation":"run","commands":[{"name":"a","path":"/bin/echo","params":{"ctx":["x"]}}]}]}`, "never referenced"},
		{"flag in permitted value", `{"capabilities":[{"operation":"run","commands":[{"name":"a","path":"/bin/echo","args":["{ctx}"],"params":{"ctx":["-o"]}}]}]}`, "flag"},
		{"empty permitted value", `{"capabilities":[{"operation":"run","commands":[{"name":"a","path":"/bin/echo","args":["{ctx}"],"params":{"ctx":[""]}}]}]}`, "empty"},
		{"bad pattern", `{"capabilities":[{"operation":"run","commands":[{"name":"a","path":"/bin/echo","args":["{ctx}"],"params":{"ctx":"("}}]}]}`, "pattern"},
		{"duplicate command", `{"capabilities":[{"operation":"run","commands":[{"name":"a","path":"/bin/echo"},{"name":"a","path":"/bin/echo"}]}]}`, "more than once"},
		{"bad command name", `{"capabilities":[{"operation":"run","commands":[{"name":"Bad Name","path":"/bin/echo"}]}]}`, "lowercase identifier"},
		{"unknown field", `{"capabilities":[{"operation":"run","commands":[{"name":"a","path":"/bin/echo"}]}],"shell":true}`, "unknown field"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, err := (registry.CommandRegistration{}).Normalize(command.Capability, json.RawMessage(test.grant))
			if err == nil {
				t.Fatalf("expected a refusal naming %q", test.want)
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error %q should name %q", err, test.want)
			}
		})
	}
}

// A grant round-trips through Normalize unchanged in meaning: the closed set
// survives as a list, the pattern as a string.
func TestNormalizeRoundTrips(t *testing.T) {
	normalized, err := (registry.CommandRegistration{}).Normalize(command.Capability, json.RawMessage(kubectlGrant))
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	again, err := (registry.CommandRegistration{}).Normalize(command.Capability, normalized)
	if err != nil {
		t.Fatalf("re-normalize: %v", err)
	}
	if string(again) != string(normalized) {
		t.Fatalf("normalize is not idempotent:\n%s\n%s", normalized, again)
	}
	if !strings.Contains(string(normalized), `["prod-eu","staging"]`) {
		t.Fatalf("the closed set did not survive normalization: %s", normalized)
	}
}

// An env value may be a secret reference, resolved host-side; a missing one
// fails the build rather than the call.
func TestEnvSecretFailsClosed(t *testing.T) {
	grant := `{"capabilities":[{"operation":"run","commands":[{
	  "name":"a","path":"/bin/echo","env":{"TOKEN":{"secret":"absent"}}}]}]}`
	var out builtin.Config
	err := (registry.CommandRegistration{}).Configure(context.Background(), json.RawMessage(grant), registry.Services{}, &out)
	if err == nil {
		t.Fatal("a grant referencing an unknown secret must fail to build")
	}
}
