package registry_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/aurora-capcompute/aurora-dispatchers/builtin"
	"github.com/aurora-capcompute/aurora-dispatchers/memory"
	"github.com/aurora-capcompute/aurora-dispatchers/registry"
	"github.com/aurora-capcompute/capcompute/sys"
)

// buildMemory builds a core.memory grant with a default process identity — the
// common case for tests that don't care which concrete session/process they run
// as. Isolation tests use buildMemoryWith to pin identities and share a store.
func buildMemory(t *testing.T, config string) builtin.Handler {
	t.Helper()
	return buildMemoryWith(t, memory.NewMapStore(),
		registry.Services{Tenant: "acme", SessionID: "s1", ProcessID: "p1"}, config)
}

// buildMemoryWith builds a core.memory grant against a caller-supplied store and
// identity, so several handlers can be pointed at one store to prove scope
// isolation (different process/session ids resolve the self-scopes to different
// physical prefixes).
func buildMemoryWith(t *testing.T, store memory.Store, services registry.Services, config string) builtin.Handler {
	t.Helper()
	services.MemoryStore = store
	built, err := registry.Default().Build(context.Background(),
		[]registry.Entry{{Syscall: memory.Capability, Config: json.RawMessage(config)}}, services)
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

func memDispatch(t *testing.T, h builtin.Handler, args string) sys.SyscallResult {
	t.Helper()
	r, err := h.DispatchCall(context.Background(),
		sys.Syscall{Name: memory.Capability, Args: json.RawMessage(args)}, sys.Authorization{})
	if err != nil {
		t.Fatalf("dispatch %s: %v", args, err)
	}
	return r
}

func memPut(t *testing.T, h builtin.Handler, scope, key, value string) {
	t.Helper()
	r := memDispatch(t, h, fmt.Sprintf(`{"operation":"put","scope":%q,"key":%q,"value":%s}`, scope, key, value))
	if r.Status() != sys.StatusResult {
		t.Fatalf("put scope=%s key=%s: %#v", scope, key, r)
	}
}

func memGet(t *testing.T, h builtin.Handler, scope, key string) memory.GetResponse {
	t.Helper()
	r := memDispatch(t, h, fmt.Sprintf(`{"operation":"get","scope":%q,"key":%q}`, scope, key))
	if r.Status() != sys.StatusResult {
		t.Fatalf("get scope=%s key=%s: %#v", scope, key, r)
	}
	var resp memory.GetResponse
	if err := json.Unmarshal(r.Result(), &resp); err != nil {
		t.Fatalf("decode get: %v", err)
	}
	return resp
}

func TestMemoryPublishesOneCapability(t *testing.T) {
	handler := buildMemory(t, `{"capabilities":[{"scope":"session","subtree":"notes","operations":["get","put","list"]}]}`)
	if !handler.Handles("core.memory") {
		t.Fatal("handler must route by the capability name core.memory")
	}
	if handler.Handles("memory.put") {
		t.Fatal("operations are ADT cases, not separate capability names")
	}
}

func TestMemoryRequiresServices(t *testing.T) {
	config := `{"capabilities":[{"scope":"shared:team","operations":["get"]}]}`
	entries := []registry.Entry{{Syscall: "core.memory", Config: json.RawMessage(config)}}
	if _, err := registry.Default().Build(context.Background(), entries,
		registry.Services{MemoryStore: memory.NewMapStore()}); err == nil || !strings.Contains(err.Error(), "Tenant") {
		t.Fatalf("err = %v, want missing-tenant error", err)
	}
	if _, err := registry.Default().Build(context.Background(), entries,
		registry.Services{Tenant: "acme"}); err == nil || !strings.Contains(err.Error(), "MemoryStore") {
		t.Fatalf("err = %v, want missing-store error", err)
	}
	// The self-scopes need the process credential; a build without it fails closed
	// rather than silently collapsing everyone's session scope into one prefix.
	sessionCfg := []registry.Entry{{Syscall: "core.memory", Config: json.RawMessage(`{"capabilities":[{"scope":"session","operations":["get"]}]}`)}}
	if _, err := registry.Default().Build(context.Background(), sessionCfg,
		registry.Services{Tenant: "acme", MemoryStore: memory.NewMapStore()}); err == nil || !strings.Contains(err.Error(), "session") {
		t.Fatalf("err = %v, want a missing session-identity error", err)
	}
}

func TestMemoryRejectsBadConfig(t *testing.T) {
	bad := []string{
		// A subtree is a chroot: no absolute, trailing, or traversal segments.
		`{"capabilities":[{"scope":"session","subtree":"/abs","operations":["get"]}]}`,
		`{"capabilities":[{"scope":"session","subtree":"trail/","operations":["get"]}]}`,
		`{"capabilities":[{"scope":"session","subtree":"a/../b","operations":["get"]}]}`,
		// Unknown operation, and an empty operation set.
		`{"capabilities":[{"scope":"session","operations":["nope"]}]}`,
		`{"capabilities":[{"scope":"session","operations":[]}]}`,
		// No mounts at all.
		`{"capabilities":[]}`,
		// There is deliberately no tenant-wide scope, and unknown scopes are refused.
		`{"capabilities":[{"scope":"tenant","operations":["get"]}]}`,
		`{"capabilities":[{"scope":"everyone","operations":["get"]}]}`,
		// A shared space needs a safe, non-empty, path-free name.
		`{"capabilities":[{"scope":"shared:","operations":["get"]}]}`,
		`{"capabilities":[{"scope":"shared:../etc","operations":["get"]}]}`,
		// One scope may be mounted only once.
		`{"capabilities":[{"scope":"session","operations":["get"]},{"scope":"session","operations":["put"]}]}`,
		// The old flat shape (top-level subtree, per-operation entries) is refused —
		// a migration guard, not a silent reinterpretation.
		`{"subtree":"notes","capabilities":[{"operation":"get"}]}`,
		`{"capabilities":[{"operation":"get"}]}`,
	}
	for _, config := range bad {
		if _, err := registry.Default().Normalize("core.memory", json.RawMessage(config)); err == nil {
			t.Fatalf("bad config accepted: %s", config)
		}
	}
	// A well-formed multi-scope grant with a subtree normalizes cleanly.
	good := `{"capabilities":[{"scope":"process","operations":["get","put"]},{"scope":"shared:team","subtree":"notes/work","operations":["get"]}]}`
	if _, err := registry.Default().Normalize("core.memory", json.RawMessage(good)); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

// Scope is a whole-mount property, and each self-scope resolves through the
// process credential to a distinct physical prefix: process is private to the
// writing process, session spans that session's processes only, and a named
// shared space is the sole way to cross sessions.
func TestMemoryScopeIsolation(t *testing.T) {
	store := memory.NewMapStore()
	cfg := `{"capabilities":[
		{"scope":"process","operations":["get","put"]},
		{"scope":"session","operations":["get","put"]},
		{"scope":"shared:team","operations":["get","put"]}
	]}`
	// Two processes in one session, and a third in a different session.
	p1 := buildMemoryWith(t, store, registry.Services{Tenant: "acme", SessionID: "s1", ProcessID: "p1"}, cfg)
	p2 := buildMemoryWith(t, store, registry.Services{Tenant: "acme", SessionID: "s1", ProcessID: "p2"}, cfg)
	p3 := buildMemoryWith(t, store, registry.Services{Tenant: "acme", SessionID: "s2", ProcessID: "p3"}, cfg)

	// process: private to the writer; a sibling process cannot read it.
	memPut(t, p1, "process", "k", `"p1-only"`)
	if got := memGet(t, p1, "process", "k"); string(got.Value) != `"p1-only"` {
		t.Fatalf("process scope did not round-trip in its own process: %+v", got)
	}
	if got := memGet(t, p2, "process", "k"); got.Found {
		t.Fatal("process scope leaked to another process")
	}

	// session: shared across the session's processes, isolated across sessions.
	memPut(t, p1, "session", "k", `"sess1"`)
	if got := memGet(t, p2, "session", "k"); string(got.Value) != `"sess1"` {
		t.Fatalf("session scope not shared across the session's processes: %+v", got)
	}
	if got := memGet(t, p3, "session", "k"); got.Found {
		t.Fatal("session scope leaked across sessions")
	}

	// shared: the one crossing — a different session reads it because it named
	// the same space.
	memPut(t, p1, "shared:team", "k", `"team"`)
	if got := memGet(t, p3, "shared:team", "k"); string(got.Value) != `"team"` {
		t.Fatalf("named shared space did not cross sessions: %+v", got)
	}
}

// The tenant is the absolute boundary: two grants that agree on session id,
// process id, scope, and key still cannot read each other, because the tenant —
// host-set from the credential, unnameable in the manifest — prefixes every
// physical key. Cross-tenant read is impossible by construction.
func TestMemoryCrossTenantIsImpossible(t *testing.T) {
	store := memory.NewMapStore()
	cfg := `{"capabilities":[{"scope":"session","operations":["get","put"]}]}`
	acme := buildMemoryWith(t, store, registry.Services{Tenant: "acme", SessionID: "s", ProcessID: "p"}, cfg)
	rival := buildMemoryWith(t, store, registry.Services{Tenant: "rival", SessionID: "s", ProcessID: "p"}, cfg)

	memPut(t, acme, "session", "secret", `"acme-only"`)
	if got := memGet(t, rival, "session", "secret"); got.Found {
		t.Fatalf("cross-tenant read succeeded (%s); tenant is not an absolute boundary", got.Value)
	}
}

// A call naming a scope the grant does not mount is denied — the grant is the
// allowlist of scopes, and an ungranted scope is not reachable.
func TestMemoryUngrantedScopeIsDenied(t *testing.T) {
	h := buildMemoryWith(t, memory.NewMapStore(),
		registry.Services{Tenant: "acme", SessionID: "s", ProcessID: "p"},
		`{"capabilities":[{"scope":"session","operations":["get","put"]}]}`)
	// process is not mounted…
	if r := memDispatch(t, h, `{"operation":"get","scope":"process","key":"k"}`); r.Status() != sys.StatusFailed || r.Errno() != sys.ErrnoDenied {
		t.Fatalf("ungranted scope = %v/%v, want failed/denied", r.Status(), r.Errno())
	}
	// …nor is a shared space the grant never named.
	if r := memDispatch(t, h, `{"operation":"get","scope":"shared:other","key":"k"}`); r.Status() != sys.StatusFailed || r.Errno() != sys.ErrnoDenied {
		t.Fatalf("ungranted shared space = %v/%v, want failed/denied", r.Status(), r.Errno())
	}
}

// With one mount the scope may be omitted; with several it is required, so a
// multi-scope call can never be silently misrouted. The handler enforces this
// even though the published schema also marks scope required — defense in depth.
func TestMemoryScopeRequiredWhenAmbiguous(t *testing.T) {
	store := memory.NewMapStore()
	single := buildMemoryWith(t, store, registry.Services{Tenant: "acme", SessionID: "s", ProcessID: "p"},
		`{"capabilities":[{"scope":"session","operations":["get","put"]}]}`)
	if r := memDispatch(t, single, `{"operation":"put","key":"k","value":1}`); r.Status() != sys.StatusResult {
		t.Fatalf("single-mount put without scope = %#v, want ok", r)
	}
	multi := buildMemoryWith(t, store, registry.Services{Tenant: "acme", SessionID: "s", ProcessID: "p"},
		`{"capabilities":[{"scope":"session","operations":["get","put"]},{"scope":"process","operations":["get","put"]}]}`)
	if r := memDispatch(t, multi, `{"operation":"put","key":"k","value":1}`); r.Status() != sys.StatusFailed || r.Errno() != sys.ErrnoDenied {
		t.Fatalf("multi-mount put without scope = %v/%v, want failed/denied", r.Status(), r.Errno())
	}
}

// Granting only some operations makes the others un-dispatchable: put is denied
// when the mount lists only get.
func TestMemoryGrantsOnlySelectedOperations(t *testing.T) {
	handler := buildMemory(t, `{"capabilities":[{"scope":"session","operations":["get"]}]}`)
	result := memDispatch(t, handler, `{"operation":"put","scope":"session","key":"k","value":1}`)
	if result.Status() != sys.StatusFailed || result.Errno() != sys.ErrnoDenied {
		t.Fatalf("put on a get-only grant = %v/%v, want failed/denied", result.Status(), result.Errno())
	}
}

// Flow policy is a per-mount property: a mount's taints guard every write into it
// and its labels ride every read out of it.
func TestMemoryMountFlow(t *testing.T) {
	handler := buildMemoryWith(t, memory.NewMapStore(),
		registry.Services{Tenant: "acme", SessionID: "s", ProcessID: "p"},
		`{"capabilities":[{"scope":"session","operations":["get","put"],"labels":["tenant_mem"],"taints":["untrusted_web"]}]}`)

	// A tainted run may not write into a mount that forbids the taint.
	tainted := sys.WithTaint(context.Background(), []string{"untrusted_web"})
	blocked, err := handler.DispatchCall(tainted,
		sys.Syscall{Name: "core.memory", Args: json.RawMessage(`{"operation":"put","scope":"session","key":"k","value":"v"}`)}, sys.Authorization{})
	if err != nil {
		t.Fatalf("dispatch put: %v", err)
	}
	if blocked.Status() != sys.StatusFailed || blocked.Errno() != sys.ErrnoDenied {
		t.Fatalf("tainted put = %v/%v, want failed/denied", blocked.Status(), blocked.Errno())
	}

	// A clean run writes, then reads the value back carrying the mount's source label.
	memPut(t, handler, "session", "k", `"v"`)
	got := memDispatch(t, handler, `{"operation":"get","scope":"session","key":"k"}`)
	if got.Status() != sys.StatusResult {
		t.Fatalf("get = %#v", got)
	}
	if labels := got.Labels(); len(labels) != 1 || labels[0] != "tenant_mem" {
		t.Fatalf("get labels = %v, want [tenant_mem]", labels)
	}
}
