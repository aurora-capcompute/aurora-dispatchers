package memory_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/aurora-capcompute/aurora-dispatchers/memory"
	"github.com/aurora-capcompute/capcompute/sys"
	"github.com/aurora-capcompute/capcompute/sys/replay"
	"github.com/aurora-capcompute/capcompute/sys/replay/tape/journaled"
)

func dispatch(t *testing.T, h memory.Handler, name, args string, auth sys.Authorization) sys.SyscallResult {
	t.Helper()
	call := sys.Syscall{Abi: sys.ABIVersion, Name: name}
	if args != "" {
		call.Args = json.RawMessage(args)
	}
	result, err := h.DispatchCall(context.Background(), call, auth)
	if err != nil {
		t.Fatalf("dispatch %s: %v", name, err)
	}
	return result
}

func TestMemoryRoundTripAcrossThreads(t *testing.T) {
	store := memory.NewMapStore()
	// Two handlers = two grants in two different threads of one tenant.
	threadOne := memory.Handler{Name: "mem", Store: store, Tenant: "acme"}
	threadTwo := memory.Handler{Name: "mem", Store: store, Tenant: "acme"}

	put := dispatch(t, threadOne, "mem.put", `{"key":"prefs/tone","value":{"formal":true}}`, sys.Authorization{})
	if put.Status() != sys.StatusResult {
		t.Fatalf("put = %#v", put)
	}

	get := dispatch(t, threadTwo, "mem.get", `{"key":"prefs/tone"}`, sys.Authorization{})
	var response memory.GetResponse
	if err := json.Unmarshal(get.Result(), &response); err != nil {
		t.Fatalf("decode get: %v", err)
	}
	if !response.Found || string(response.Value) != `{"formal":true}` {
		t.Fatalf("get = %+v; cross-thread value not shared", response)
	}

	list := dispatch(t, threadTwo, "mem.list", `{"prefix":"prefs"}`, sys.Authorization{})
	var listed memory.ListResponse
	if err := json.Unmarshal(list.Result(), &listed); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(listed.Keys) != 1 || listed.Keys[0] != "prefs/tone" {
		t.Fatalf("list = %+v", listed)
	}
}

func TestMemoryTenantsAreIsolated(t *testing.T) {
	store := memory.NewMapStore()
	acme := memory.Handler{Name: "mem", Store: store, Tenant: "acme"}
	rival := memory.Handler{Name: "mem", Store: store, Tenant: "rival"}

	dispatch(t, acme, "mem.put", `{"key":"secret","value":"acme-only"}`, sys.Authorization{})

	get := dispatch(t, rival, "mem.get", `{"key":"secret"}`, sys.Authorization{})
	var response memory.GetResponse
	if err := json.Unmarshal(get.Result(), &response); err != nil {
		t.Fatalf("decode get: %v", err)
	}
	if response.Found {
		t.Fatal("tenant isolation violated: rival read acme's key")
	}
}

func TestMemorySubtreeChroot(t *testing.T) {
	store := memory.NewMapStore()
	full := memory.Handler{Name: "mem", Store: store, Tenant: "acme"}
	dispatch(t, full, "mem.put", `{"key":"secret/root-key","value":"hidden"}`, sys.Authorization{})
	dispatch(t, full, "mem.put", `{"key":"notes/today","value":"visible"}`, sys.Authorization{})

	notes := memory.Handler{Name: "mem", Store: store, Tenant: "acme", Subtree: "notes"}

	// Inside the subtree: relative keys resolve under notes/.
	get := dispatch(t, notes, "mem.get", `{"key":"today"}`, sys.Authorization{})
	var response memory.GetResponse
	if err := json.Unmarshal(get.Result(), &response); err != nil {
		t.Fatalf("decode get: %v", err)
	}
	if !response.Found || string(response.Value) != `"visible"` {
		t.Fatalf("subtree get = %+v", response)
	}

	// Escape attempts are rejected, not resolved.
	for _, key := range []string{"../secret/root-key", "a/../../secret", "/secret/root-key", "a//b", "."} {
		result := dispatch(t, notes, "mem.get", `{"key":"`+key+`"}`, sys.Authorization{})
		if result.Status() != sys.StatusFailed || result.Errno() != sys.ErrnoInvalidArgs {
			t.Fatalf("escape %q = %#v, want failed/invalid_args", key, result)
		}
	}

	// Listing is confined to the subtree and returns relative keys.
	list := dispatch(t, notes, "mem.list", "", sys.Authorization{})
	var listed memory.ListResponse
	if err := json.Unmarshal(list.Result(), &listed); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(listed.Keys) != 1 || listed.Keys[0] != "today" {
		t.Fatalf("subtree list = %+v, want [today]", listed)
	}
}

func TestMemoryPutApprovalGate(t *testing.T) {
	store := memory.NewMapStore()
	gated := memory.Handler{Name: "mem", Store: store, Tenant: "acme", RequireApprovalOnPut: true}

	// Unapproved writes yield a human task.
	result := dispatch(t, gated, "mem.put", `{"key":"prefs/tone","value":1}`, sys.Authorization{})
	if result.Status() != sys.StatusYield {
		t.Fatalf("unapproved put = %#v, want yield", result)
	}
	if _, found, _ := store.Get(context.Background(), "acme", "prefs/tone"); found {
		t.Fatal("unapproved put reached the store")
	}

	// The replayed, approved call proceeds.
	result = dispatch(t, gated, "mem.put", `{"key":"prefs/tone","value":1}`, sys.Authorization{Decision: sys.Approved, Actor: "alice"})
	if result.Status() != sys.StatusResult {
		t.Fatalf("approved put = %#v", result)
	}
	// Reads are never gated.
	if result := dispatch(t, gated, "mem.get", `{"key":"prefs/tone"}`, sys.Authorization{}); result.Status() != sys.StatusResult {
		t.Fatalf("get under approval gate = %#v", result)
	}
}

type memJournal struct {
	header    journaled.Header
	hasHeader bool
	records   []journaled.Record
}

func (j *memJournal) Header() (journaled.Header, bool, error) { return j.header, j.hasHeader, nil }
func (j *memJournal) SetHeader(header journaled.Header) error {
	j.header = header
	j.hasHeader = true
	return nil
}
func (j *memJournal) Load(idx int) (journaled.Record, error) { return j.records[idx], nil }
func (j *memJournal) Append(record journaled.Record) error {
	j.records = append(j.records, record)
	return nil
}
func (j *memJournal) Length() int { return len(j.records) }

type handlerDispatcher struct{ handler memory.Handler }

func (d handlerDispatcher) Dispatch(ctx context.Context, _ string, call sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	return d.handler.DispatchCall(ctx, call, auth)
}
func (d handlerDispatcher) Capabilities() []sys.Capability { return nil }

// The determinism law applied to shared mutable state: a journaled read is
// replayed from the journal, not re-read from the (since mutated) store.
func TestMemoryReadReplaysJournaledValue(t *testing.T) {
	store := memory.NewMapStore()
	handler := memory.Handler{Name: "mem", Store: store, Tenant: "acme"}
	journal := &memJournal{}
	header := journaled.Header{ABI: sys.ABIVersion, Program: "sha256:test", Run: "run-1"}

	chain := func(t *testing.T) sys.Dispatcher[string] {
		t.Helper()
		tape, err := journaled.NewTape(journal, header)
		if err != nil {
			t.Fatalf("new tape: %v", err)
		}
		return replay.NewDispatcher[string](tape, handlerDispatcher{handler})
	}

	if err := store.Put(context.Background(), "acme", "prefs/tone", json.RawMessage(`"casual"`)); err != nil {
		t.Fatalf("seed store: %v", err)
	}
	read := sys.Syscall{Abi: sys.ABIVersion, Name: "mem.get", Args: json.RawMessage(`{"key":"prefs/tone"}`)}

	first, err := chain(t).Dispatch(context.Background(), "run-1", read, sys.Authorization{})
	if err != nil {
		t.Fatalf("first read: %v", err)
	}

	// Another thread mutates the shared value…
	if err := store.Put(context.Background(), "acme", "prefs/tone", json.RawMessage(`"formal"`)); err != nil {
		t.Fatalf("mutate store: %v", err)
	}

	// …and the crash-replayed run still observes what it originally read.
	replayed, err := chain(t).Dispatch(context.Background(), "run-1", read, sys.Authorization{})
	if err != nil {
		t.Fatalf("replayed read: %v", err)
	}
	if string(replayed.Result()) != string(first.Result()) {
		t.Fatalf("replay diverged from journal: %s vs %s", replayed.Result(), first.Result())
	}
	var response memory.GetResponse
	if err := json.Unmarshal(replayed.Result(), &response); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(response.Value) != `"casual"` {
		t.Fatalf("replayed value = %s, want the journaled original", response.Value)
	}
}
