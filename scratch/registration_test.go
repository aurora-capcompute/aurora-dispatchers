package scratch_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aurora-capcompute/aurora-capcompute/capability"
	"github.com/aurora-capcompute/aurora-dispatchers/registry"
	"github.com/aurora-capcompute/aurora-dispatchers/scratch"
	"github.com/aurora-capcompute/capcompute/sys"
)

func buildScratchTable(t *testing.T, config string, store scratch.Store) *capability.Table {
	t.Helper()
	built, err := registry.New(scratch.Registration{Store: store}).Build(context.Background(),
		[]registry.Entry{{Syscall: scratch.Capability, Config: json.RawMessage(config)}},
		registry.Services{},
	)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(built.Descriptors()) != 1 || built.Descriptors()[0].Name != scratch.Capability {
		t.Fatalf("capabilities = %+v, want one named %s", built.Descriptors(), scratch.Capability)
	}
	assertMenuOffers(t, built, scratch.Capability)
	if len(built.Entries()) == 0 {
		t.Fatalf("no operations indexed: %+v", built.Descriptors())
	}
	return built
}

func buildScratch(t *testing.T, config string, store scratch.Store) sys.Dispatcher[string] {
	return capability.NewDispatcher[string](buildScratchTable(t, config, store))
}

func scratchCall(t *testing.T, h sys.Dispatcher[string], args string) sys.SyscallResult {
	t.Helper()
	res, err := h.Dispatch(context.Background(), "p1",
		sys.Syscall{Name: scratch.Capability, Args: json.RawMessage(args)}, sys.Authorization{})
	if err != nil {
		t.Fatalf("dispatch %s: %v", args, err)
	}
	return res
}

// core.scratch routes by its own capability name.
func TestScratchRoutesByName(t *testing.T) {
	table := buildScratchTable(t, `{"capabilities":[{"operation":"put"},{"operation":"get"},{"operation":"search"}]}`, scratch.NewMapStore())
	if got := table.Operations(scratch.Capability); len(got) != 3 {
		t.Fatalf("operations = %v, want get/put/search under %s", got, scratch.Capability)
	}
	if len(table.Operations("core.internet")) != 0 {
		t.Fatal("scratch must answer to its own name alone")
	}
}

// put then search round-trips through the session's store — the offload path
// (stash a page, grep it later).
func TestScratchRoundTrips(t *testing.T) {
	handler := buildScratch(t, `{"capabilities":[{"operation":"put"},{"operation":"search"}]}`, scratch.NewMapStore())
	if put := scratchCall(t, handler, `{"operation":"put","key":"fetch/x","value":"the quick brown fox"}`); put.Status() != sys.StatusResult {
		t.Fatalf("put status = %v", put.Status())
	}
	got := scratchCall(t, handler, `{"operation":"search","key":"fetch/x","pattern":"brown"}`)
	if got.Status() != sys.StatusResult || !strings.Contains(string(got.Result()), "brown") {
		t.Fatalf("search = %v / %s, want a match on 'brown'", got.Status(), got.Result())
	}
}

// Every build — every quantum of every process — over one session's store sees
// the same data: what one process writes, a later process (or the same one,
// resumed) reads. Which store a build gets is the host's choice; isolating
// sessions from each other is tested where the host binds them.
func TestScratchBuildsShareTheirSessionStore(t *testing.T) {
	session := scratch.NewMapStore()
	writer := buildScratch(t, `{"capabilities":[{"operation":"put"}]}`, session)
	reader := buildScratch(t, `{"capabilities":[{"operation":"get"}]}`, session)
	if put := scratchCall(t, writer, `{"operation":"put","key":"notes/plan","value":"step two"}`); put.Status() != sys.StatusResult {
		t.Fatalf("put = %v", put.Status())
	}
	got := scratchCall(t, reader, `{"operation":"get","key":"notes/plan"}`)
	if got.Status() != sys.StatusResult || !strings.Contains(string(got.Result()), `"step two"`) {
		t.Fatalf("get = %v / %s, want the value the other build wrote", got.Status(), got.Result())
	}
}

// The door check builds without a process, so without a store: the config is
// still validated. It serves no call.
func TestScratchConfigCheckNeedsNoStore(t *testing.T) {
	config := json.RawMessage(`{"capabilities":[{"operation":"put"}]}`)
	if _, err := registryValidate(scratch.Registration{}, scratch.Capability, config); err != nil {
		t.Fatalf("door check refused a valid grant: %v", err)
	}
}
