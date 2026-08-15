package registry_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aurora-capcompute/aurora-dispatchers/builtin"
	"github.com/aurora-capcompute/aurora-dispatchers/registry"
	"github.com/aurora-capcompute/capcompute/sys"
)

func buildScratchTable(t *testing.T, config string) *builtin.Table {
	t.Helper()
	// Unlike core.memory, scratch needs no Services — it owns a fresh in-memory
	// store per build (i.e. per process).
	built, err := registry.New(registry.ScratchRegistration{}).Build(context.Background(),
		[]registry.Entry{{Syscall: registry.ScratchCapability, Config: json.RawMessage(config)}},
		registry.Services{},
	)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(built.Capabilities()) != 1 || built.Capabilities()[0].Name != registry.ScratchCapability {
		t.Fatalf("capabilities = %+v, want one named %s", built.Capabilities(), registry.ScratchCapability)
	}
	if !strings.Contains(string(built.Capabilities()[0].InputSchema), `"oneOf"`) {
		t.Fatalf("input schema is not a oneOf ADT: %s", built.Capabilities()[0].InputSchema)
	}
	if len(built.Entries()) == 0 {
		t.Fatalf("no operations indexed: %+v", built.Capabilities())
	}
	return built
}

func buildScratch(t *testing.T, config string) builtin.Handler {
	return buildScratchTable(t, config).Entries()[0].Handler
}

func scratchCall(t *testing.T, h builtin.Handler, args string) sys.SyscallResult {
	t.Helper()
	res, err := h.DispatchCall(context.Background(),
		sys.Syscall{Name: registry.ScratchCapability, Args: json.RawMessage(args)}, sys.Authorization{})
	if err != nil {
		t.Fatalf("dispatch %s: %v", args, err)
	}
	return res
}

// core.scratch routes by the capability name and, unlike core.memory, requires
// no host Services.
func TestScratchRoutesByNameAndNeedsNoServices(t *testing.T) {
	table := buildScratchTable(t, `{"capabilities":[{"operation":"put"},{"operation":"get"},{"operation":"search"}]}`)
	if got := table.Operations(registry.ScratchCapability); len(got) != 3 {
		t.Fatalf("operations = %v, want get/put/search under %s", got, registry.ScratchCapability)
	}
	if len(table.Operations("core.memory")) != 0 {
		t.Fatal("scratch must not answer to core.memory")
	}
}

// put then search round-trips through the process's own store — the offload
// path (stash a page, grep it later).
func TestScratchRoundTrips(t *testing.T) {
	handler := buildScratch(t, `{"capabilities":[{"operation":"put"},{"operation":"search"}]}`)
	if put := scratchCall(t, handler, `{"operation":"put","key":"fetch/x","value":"the quick brown fox"}`); put.Status() != sys.StatusResult {
		t.Fatalf("put status = %v", put.Status())
	}
	got := scratchCall(t, handler, `{"operation":"search","key":"fetch/x","pattern":"brown"}`)
	if got.Status() != sys.StatusResult || !strings.Contains(string(got.Result()), "brown") {
		t.Fatalf("search = %v / %s, want a match on 'brown'", got.Status(), got.Result())
	}
}

// Each build owns a distinct store: a key written to one process's scratch is
// invisible to another's. This is the whole point — process-scoped, never
// shared, so offloaded internet data cannot leak across processes.
func TestScratchIsProcessIsolated(t *testing.T) {
	a := buildScratch(t, `{"capabilities":[{"operation":"put"},{"operation":"get"}]}`)
	b := buildScratch(t, `{"capabilities":[{"operation":"put"},{"operation":"get"}]}`)
	if put := scratchCall(t, a, `{"operation":"put","key":"secret","value":"a-only"}`); put.Status() != sys.StatusResult {
		t.Fatalf("put into a = %v", put.Status())
	}
	got := scratchCall(t, b, `{"operation":"get","key":"secret"}`)
	if got.Status() != sys.StatusResult {
		t.Fatalf("get from b = %v", got.Status())
	}
	if !strings.Contains(string(got.Result()), `"found":false`) || strings.Contains(string(got.Result()), "a-only") {
		t.Fatalf("b saw a's key: %s — scratch is not isolated", got.Result())
	}
}
