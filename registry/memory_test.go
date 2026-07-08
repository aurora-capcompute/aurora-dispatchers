package registry_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aurora-capcompute/aurora-dispatchers/builtin"
	"github.com/aurora-capcompute/aurora-dispatchers/memory"
	"github.com/aurora-capcompute/aurora-dispatchers/registry"
	"github.com/aurora-capcompute/capcompute/sys"
)

func buildMemory(t *testing.T, config string) builtin.Handler {
	t.Helper()
	built, err := registry.Default().Build(context.Background(),
		[]registry.Entry{{Syscall: "core.memory", Config: json.RawMessage(config)}},
		registry.Services{Tenant: "acme", MemoryStore: memory.NewMapStore()},
	)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(built.Capabilities) != 1 || built.Capabilities[0].Name != memory.Capability {
		t.Fatalf("capabilities = %+v, want one named %s", built.Capabilities, memory.Capability)
	}
	if !strings.Contains(string(built.Capabilities[0].InputSchema), `"oneOf"`) {
		t.Fatalf("input schema is not a oneOf ADT: %s", built.Capabilities[0].InputSchema)
	}
	if len(built.Handlers) != 1 {
		t.Fatalf("handlers = %+v", built.Handlers)
	}
	return built.Handlers[0]
}

func TestMemoryPublishesOneCapability(t *testing.T) {
	handler := buildMemory(t, `{"capabilities":[{"operation":"get"},{"operation":"put"},{"operation":"list"}],"subtree":"notes"}`)
	if !handler.Handles("core.memory") {
		t.Fatal("handler must route by the capability name core.memory")
	}
	if handler.Handles("memory.put") {
		t.Fatal("operations are ADT cases, not separate capability names")
	}
}

func TestMemoryRequiresServices(t *testing.T) {
	entries := []registry.Entry{{Syscall: "core.memory", Config: json.RawMessage(`{"capabilities":[{"operation":"get"}]}`)}}
	if _, err := registry.Default().Build(context.Background(), entries,
		registry.Services{MemoryStore: memory.NewMapStore()}); err == nil || !strings.Contains(err.Error(), "Tenant") {
		t.Fatalf("err = %v, want missing-tenant error", err)
	}
	if _, err := registry.Default().Build(context.Background(), entries,
		registry.Services{Tenant: "acme"}); err == nil || !strings.Contains(err.Error(), "MemoryStore") {
		t.Fatalf("err = %v, want missing-store error", err)
	}
}

func TestMemoryRejectsBadConfig(t *testing.T) {
	for _, subtree := range []string{"/abs", "trail/", "a/../b"} {
		_, err := registry.Default().Normalize("core.memory", json.RawMessage(`{"capabilities":[{"operation":"get"}],"subtree":"`+subtree+`"}`))
		if err == nil {
			t.Fatalf("subtree %q accepted", subtree)
		}
	}
	if _, err := registry.Default().Normalize("core.memory", json.RawMessage(`{"capabilities":[{"operation":"get"}],"subtree":"notes/work"}`)); err != nil {
		t.Fatalf("valid subtree rejected: %v", err)
	}
	if _, err := registry.Default().Normalize("core.memory", json.RawMessage(`{"capabilities":[{"operation":"nope"}]}`)); err == nil {
		t.Fatal("unknown operation accepted")
	}
	if _, err := registry.Default().Normalize("core.memory", json.RawMessage(`{"capabilities":[]}`)); err == nil {
		t.Fatal("empty capabilities accepted")
	}
}

// Granting only some operations makes the others un-dispatchable: put is denied
// when the grant lists only get.
func TestMemoryGrantsOnlySelectedOperations(t *testing.T) {
	handler := buildMemory(t, `{"capabilities":[{"operation":"get"}]}`)
	result, err := handler.DispatchCall(context.Background(),
		sys.Syscall{Name: "core.memory", Args: json.RawMessage(`{"operation":"put","key":"k","value":1}`)}, sys.Authorization{})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if result.Status() != sys.StatusFailed || result.Errno() != sys.ErrnoDenied {
		t.Fatalf("put on a get-only grant = %v/%v, want failed/denied", result.Status(), result.Errno())
	}
}

// Per-operation flow: a put whose grant forbids `untrusted_web` is refused when
// the run has observed that taint, and a get's source labels ride its result.
func TestMemoryPerOperationFlow(t *testing.T) {
	handler := buildMemory(t, `{"capabilities":[
		{"operation":"get","labels":["tenant_mem"]},
		{"operation":"put","taints":["untrusted_web"]}
	]}`)

	// A tainted run may not write.
	tainted := sys.WithTaint(context.Background(), []string{"untrusted_web"})
	blocked, err := handler.DispatchCall(tainted,
		sys.Syscall{Name: "core.memory", Args: json.RawMessage(`{"operation":"put","key":"k","value":"v"}`)}, sys.Authorization{})
	if err != nil {
		t.Fatalf("dispatch put: %v", err)
	}
	if blocked.Status() != sys.StatusFailed || blocked.Errno() != sys.ErrnoDenied {
		t.Fatalf("tainted put = %v/%v, want failed/denied", blocked.Status(), blocked.Errno())
	}

	// A clean run may write, then read the value back carrying the get source label.
	if put, err := handler.DispatchCall(context.Background(),
		sys.Syscall{Name: "core.memory", Args: json.RawMessage(`{"operation":"put","key":"k","value":"v"}`)}, sys.Authorization{}); err != nil || put.Status() != sys.StatusResult {
		t.Fatalf("clean put = %v (%v)", put.Status(), err)
	}
	got, err := handler.DispatchCall(context.Background(),
		sys.Syscall{Name: "core.memory", Args: json.RawMessage(`{"operation":"get","key":"k"}`)}, sys.Authorization{})
	if err != nil || got.Status() != sys.StatusResult {
		t.Fatalf("get = %v (%v)", got.Status(), err)
	}
	if labels := got.Labels(); len(labels) != 1 || labels[0] != "tenant_mem" {
		t.Fatalf("get labels = %v, want [tenant_mem]", labels)
	}
}
