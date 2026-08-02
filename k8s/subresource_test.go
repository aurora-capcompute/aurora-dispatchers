package k8s

// Kubernetes subresources are where "GET is a read" stops being true. GET on
// pods/{name}/exec or /attach upgrades the connection and runs a command inside
// a container; .../portforward opens a tunnel; services|pods|nodes/{name}/proxy
// forwards an arbitrary request — including a write — to the backend, with the
// driver's bearer token attached. Any of those reachable would make this a
// cluster-mutating driver no matter that every request it builds is a GET.
//
// They are unreachable because a subresource needs a second path segment, and
// nothing that reaches the path builder may contain a slash: resource, namespace
// and name are each pattern-validated first, and the path is assembled from the
// grant's own group/version/resource rather than the guest's strings. These
// tests pin that, from both directions — the guest's request and the host's
// configuration.

import (
	"context"
	"strings"
	"testing"

	"github.com/aurora-capcompute/capcompute/sys"
)

// A guest may not reach a subresource through any field it controls.
func TestSubresourceEscapeIsRefused(t *testing.T) {
	srv := newRecordingServer()
	defer srv.Close()
	h := newTestHandler(srv, fixtureResources())
	ctx := context.Background()

	escapes := []struct {
		name string
		args string
	}{
		{"exec via name", `{"operation":"get","resource":"pods","namespace":"default","name":"web-0/exec"}`},
		{"attach via name", `{"operation":"get","resource":"pods","namespace":"default","name":"web-0/attach"}`},
		{"portforward via name", `{"operation":"get","resource":"pods","namespace":"default","name":"web-0/portforward"}`},
		{"proxy via name", `{"operation":"get","resource":"pods","namespace":"default","name":"web-0/proxy/write"}`},
		{"log via name", `{"operation":"get","resource":"pods","namespace":"default","name":"web-0/log"}`},
		{"exec via resource", `{"operation":"get","resource":"pods/exec","namespace":"default","name":"web-0"}`},
		{"proxy via resource", `{"operation":"get","resource":"services/proxy","namespace":"default","name":"api"}`},
		{"encoded slash in name", `{"operation":"get","resource":"pods","namespace":"default","name":"web-0%2Fexec"}`},
		{"subresource via namespace", `{"operation":"get","resource":"pods","namespace":"default/pods/web-0/exec","name":"x"}`},
	}
	for _, escape := range escapes {
		t.Run(escape.name, func(t *testing.T) {
			before := func() int { _, _, _, _, _, hits := srv.snapshot(); return hits }()
			result := dispatch(t, h, ctx, escape.args)
			if result.Status() != sys.StatusFailed {
				t.Fatalf("expected a refusal, got %v (%s)", result.Status(), result.Message())
			}
			if _, _, _, _, _, after := srv.snapshot(); after != before {
				t.Fatalf("the request reached the API server: %s", escape.args)
			}
		})
	}
}

// Even a granted, well-formed read builds a path with exactly one segment after
// the resource — the object name. A subresource needs a second, so the shape of
// the path the driver produces is itself the guarantee.
func TestBuiltPathHasNoSubresourceSegment(t *testing.T) {
	srv := newRecordingServer()
	defer srv.Close()
	h := newTestHandler(srv, fixtureResources())

	reads := []string{
		`{"operation":"get","resource":"pods","namespace":"default","name":"web-0"}`,
		`{"operation":"get","resource":"nodes","name":"node-1"}`,
		`{"operation":"get","group":"apps","resource":"deployments","namespace":"default","name":"web"}`,
	}
	for _, args := range reads {
		if result := dispatch(t, h, context.Background(), args); result.Status() != sys.StatusResult {
			t.Fatalf("%s => %v (%s); the fixture should grant this read", args, result.Status(), result.Message())
		}
		_, path, _, _, _, _ := srv.snapshot()
		// .../<resource>/<name> and nothing further.
		segments := strings.Split(strings.Trim(path, "/"), "/")
		last := segments[len(segments)-2:]
		if len(last) != 2 {
			t.Fatalf("path %q is too short to check", path)
		}
		if strings.Contains(last[1], "/") {
			t.Fatalf("path %q carries a segment past the object name", path)
		}
		for _, subresource := range []string{"exec", "attach", "portforward", "proxy", "log", "eviction", "binding", "scale", "status"} {
			if last[len(last)-1] == subresource {
				t.Fatalf("path %q ends in the %q subresource", path, subresource)
			}
		}
	}
}

// The host cannot configure a subresource either: a grant naming one is refused
// at normalization, so a misconfigured manifest fails closed rather than
// widening the driver.
func TestSubresourceCannotBeGranted(t *testing.T) {
	for _, resource := range []string{"pods/exec", "pods/portforward", "services/proxy", "pods/log", "PODS", "pods.v1", "pods-x"} {
		if err := ValidateResourceIdentity("", "v1", resource); err == nil {
			t.Fatalf("resource %q was accepted as a grant; a subresource or non-plain resource name must be refused", resource)
		}
	}
	// The plain plural forms it is meant to admit still pass.
	for _, resource := range []string{"pods", "nodes", "deployments", "configmaps", "secrets"} {
		if err := ValidateResourceIdentity("", "v1", resource); err != nil {
			t.Fatalf("resource %q must be grantable: %v", resource, err)
		}
	}
}
