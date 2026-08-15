package builtin_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aurora-capcompute/aurora-dispatchers/builtin"
	"github.com/aurora-capcompute/capcompute/sys"
)

// stub records being reached, so a test can tell "routed here" from "refused".
type stub struct{ called int }

func (s *stub) DispatchCall(context.Context, sys.Syscall, sys.Authorization) (sys.SyscallResult, error) {
	s.called++
	return sys.Result([]byte(`"served"`)), nil
}

func entry(syscall, operation string, handler builtin.Handler) builtin.Entry {
	return builtin.Entry{
		Key:     builtin.Key{Syscall: syscall, Operation: operation},
		Handler: handler,
	}
}

func call(name, args string) sys.Syscall {
	return sys.Syscall{Abi: sys.ABIVersion, Name: name, Args: json.RawMessage(args)}
}

func table(t *testing.T, syscall string, discriminator []string, entries ...builtin.Entry) *builtin.Table {
	t.Helper()
	tbl := builtin.NewTable()
	if err := tbl.Add(builtin.Contribution{
		Discriminator: discriminator, Entries: entries, Capability: sys.Capability{Name: syscall},
	}); err != nil {
		t.Fatalf("add: %v", err)
	}
	return tbl
}

// The operation in the args selects the entry, and only that entry runs.
func TestDispatchRoutesByOperation(t *testing.T) {
	get, put := &stub{}, &stub{}
	tbl := table(t, "core.memory", []string{"operation"},
		entry("core.memory", "get", get), entry("core.memory", "put", put))

	result, err := builtin.New[struct{}](tbl).Dispatch(
		context.Background(), struct{}{}, call("core.memory", `{"operation":"put"}`), sys.Authorization{})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if result.Status() != sys.StatusResult {
		t.Fatalf("status = %s, want a result", result.Status())
	}
	if get.called != 0 || put.called != 1 {
		t.Fatalf("get=%d put=%d, want the put entry alone", get.called, put.called)
	}
}

// One handler may back several entries — the internet client serving GET and
// POST — and the entry, not the handler, is what the call matched.
func TestOneHandlerMayBackSeveralEntries(t *testing.T) {
	shared := &stub{}
	tbl := table(t, "core.internet", []string{"method"},
		entry("core.internet", "GET", shared), entry("core.internet", "POST", shared))

	dispatcher := builtin.New[struct{}](tbl)
	for _, method := range []string{"GET", "POST"} {
		if _, err := dispatcher.Dispatch(context.Background(), struct{}{},
			call("core.internet", `{"method":"`+method+`"}`), sys.Authorization{}); err != nil {
			t.Fatalf("dispatch %s: %v", method, err)
		}
	}
	if shared.called != 2 {
		t.Fatalf("handler called %d times, want 2", shared.called)
	}
}

// An operation outside the grant is denied, and the refusal names what is
// granted rather than leaving the caller to guess.
func TestUngrantedOperationIsDeniedAndNamesTheAlternatives(t *testing.T) {
	tbl := table(t, "core.memory", []string{"operation"},
		entry("core.memory", "get", &stub{}), entry("core.memory", "put", &stub{}))

	result, _ := builtin.New[struct{}](tbl).Dispatch(
		context.Background(), struct{}{}, call("core.memory", `{"operation":"drop"}`), sys.Authorization{})
	if result.Errno() != sys.ErrnoDenied {
		t.Fatalf("errno = %v, want denied", result.Errno())
	}
	if !strings.Contains(result.Message(), `"drop"`) || !strings.Contains(result.Message(), "get, put") {
		t.Fatalf("message = %q, want it to name the refused and the granted", result.Message())
	}
}

// Nothing is canonicalized: the discriminator is matched exactly, so a
// near miss is a precise refusal rather than a silent correction.
func TestDiscriminatorIsMatchedExactly(t *testing.T) {
	served := &stub{}
	tbl := table(t, "core.internet", []string{"method"}, entry("core.internet", "GET", served))

	result, _ := builtin.New[struct{}](tbl).Dispatch(
		context.Background(), struct{}{}, call("core.internet", `{"method":"get"}`), sys.Authorization{})
	if result.Errno() != sys.ErrnoDenied {
		t.Fatalf("errno = %v, want denied for a case mismatch", result.Errno())
	}
	if served.called != 0 {
		t.Fatal("a case mismatch reached the handler")
	}
}

// A syscall nothing serves is a denial, not a routing miss: the table is the
// grant.
func TestUnservedSyscallIsDenied(t *testing.T) {
	tbl := table(t, "core.memory", []string{"operation"}, entry("core.memory", "get", &stub{}))

	result, _ := builtin.New[struct{}](tbl).Dispatch(
		context.Background(), struct{}{}, call("core.internet", `{"method":"GET"}`), sys.Authorization{})
	if result.Errno() != sys.ErrnoDenied {
		t.Fatalf("errno = %v, want denied", result.Errno())
	}
}

// Arguments that cannot yield a case name at all are the caller's mistake,
// reported as invalid arguments. An *absent* property is not that: it reads as
// empty and names a case in its own right — which is how core.memory's bare
// selector names a single-mount grant — so it is denied if that case is not
// granted, never mistaken for a malformed call.
func TestUnreadableDiscriminatorIsAnArgumentError(t *testing.T) {
	tbl := table(t, "core.memory", []string{"operation"}, entry("core.memory", "get", &stub{}))
	dispatcher := builtin.New[struct{}](tbl)

	for _, args := range []string{`{"operation":7}`, `"not an object"`} {
		result, err := dispatcher.Dispatch(context.Background(), struct{}{}, call("core.memory", args), sys.Authorization{})
		if err != nil {
			t.Fatalf("dispatch %s: %v", args, err)
		}
		if result.Errno() != sys.ErrnoInvalidArgs {
			t.Fatalf("args %s = %v, want invalid-args", args, result.Errno())
		}
	}
	absent, _ := dispatcher.Dispatch(context.Background(), struct{}{}, call("core.memory", `{}`), sys.Authorization{})
	if absent.Errno() != sys.ErrnoDenied {
		t.Fatalf("absent discriminator = %v, want denied — the empty case is a case", absent.Errno())
	}
}

// A case may be a tuple: core.memory's is (operation, scope, space), because
// one operation on two mounts is two cases carrying two policies.
func TestCaseMayBeATuple(t *testing.T) {
	session, shared := &stub{}, &stub{}
	sessionGet := entry("core.memory", "get\x00session\x00", session)
	sessionGet.Labels = []string{"session_data"}
	sharedGet := entry("core.memory", "get\x00shared\x00notes", shared)
	sharedGet.Labels = []string{"shared_data"}
	tbl := table(t, "core.memory", []string{"operation", "scope", "space"}, sessionGet, sharedGet)
	dispatcher := builtin.New[struct{}](tbl)

	if _, err := dispatcher.Dispatch(context.Background(), struct{}{},
		call("core.memory", `{"operation":"get","scope":"shared","space":"notes"}`), sys.Authorization{}); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if session.called != 0 || shared.called != 1 {
		t.Fatalf("session=%d shared=%d, want the shared mount alone", session.called, shared.called)
	}
	// Each mount publishes its own policy — the whole reason the case is a tuple.
	published := tbl.Capabilities()[0]
	resolved, ok := published.FindOperation(json.RawMessage(`{"operation":"get","scope":"session"}`))
	if !ok || len(resolved.Labels) != 1 || resolved.Labels[0] != "session_data" {
		t.Fatalf("resolved = %+v ok=%v, want the session mount's own labels", resolved, ok)
	}
}

// A syscall that is one operation carries no discriminator at all.
func TestSingleOperationSyscall(t *testing.T) {
	served := &stub{}
	tbl := table(t, "sys.log", nil, entry("sys.log", "", served))

	if _, err := builtin.New[struct{}](tbl).Dispatch(context.Background(), struct{}{},
		call("sys.log", `{"message":"hi"}`), sys.Authorization{}); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if served.called != 1 {
		t.Fatal("the single-operation entry was not reached")
	}
}

// Two grants serving one operation is a manifest that means two things at once.
// The old linear scan answered it by picking whichever was appended first.
func TestDuplicateOperationIsRefused(t *testing.T) {
	tbl := builtin.NewTable()
	err := tbl.Add(builtin.Contribution{
		Discriminator: []string{"operation"},
		Entries: []builtin.Entry{
			entry("core.memory", "get", &stub{}),
			entry("core.memory", "get", &stub{}),
		},
		Capability: sys.Capability{Name: "core.memory"},
	})
	if err == nil || !strings.Contains(err.Error(), "granted twice") {
		t.Fatalf("err = %v, want a duplicate refusal", err)
	}
}

// The same syscall cannot be served by two families.
func TestDuplicateSyscallIsRefused(t *testing.T) {
	tbl := table(t, "core.memory", []string{"operation"}, entry("core.memory", "get", &stub{}))
	err := tbl.Add(builtin.Contribution{
		Discriminator: []string{"operation"},
		Entries:       []builtin.Entry{entry("core.memory", "put", &stub{})},
		Capability:    sys.Capability{Name: "core.memory"},
	})
	if err == nil || !strings.Contains(err.Error(), "served twice") {
		t.Fatalf("err = %v, want a duplicate-syscall refusal", err)
	}
}

// The index is enumerable — the thing the old capability set could not give,
// since its operations existed only inside a oneOf schema.
func TestEntriesAreEnumerable(t *testing.T) {
	tbl := table(t, "core.memory", []string{"operation"},
		entry("core.memory", "put", &stub{}), entry("core.memory", "get", &stub{}))

	got := tbl.Entries()
	if len(got) != 2 || got[0].Key.Operation != "get" || got[1].Key.Operation != "put" {
		t.Fatalf("entries = %+v, want get then put", got)
	}
	if ops := tbl.Operations("core.memory"); len(ops) != 2 || ops[0] != "get" {
		t.Fatalf("operations = %v", ops)
	}
}

// Hiding a grant keeps its operations dispatchable and takes the capability off
// the discoverable menu.
func TestHideKeepsOperationsDispatchable(t *testing.T) {
	served := &stub{}
	tbl := table(t, "core.memory", []string{"operation"}, entry("core.memory", "get", served))
	tbl.Hide("core.memory")

	if caps := tbl.Capabilities(); len(caps) != 1 || !caps[0].Hidden {
		t.Fatalf("capabilities = %+v, want the one capability hidden", caps)
	}
	if _, err := builtin.New[struct{}](tbl).Dispatch(context.Background(), struct{}{},
		call("core.memory", `{"operation":"get"}`), sys.Authorization{}); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if served.called != 1 {
		t.Fatal("a hidden capability must stay dispatchable")
	}
}

// Approval is the entry's and is enforced in one place, below the replay tape,
// so the yield and the human's answer are journaled exactly once and no driver
// has to remember to ask. Moved here from filesystem, which used to do it.
func TestApprovalIsEnforcedFromTheEntry(t *testing.T) {
	served := &stub{}
	gated := entry("core.filesystem", "read", served)
	gated.RequireApproval = true
	gated.Description = "read a file"
	tbl := table(t, "core.filesystem", []string{"operation"}, gated)
	dispatcher := builtin.New[struct{}](tbl)

	pending, err := dispatcher.Dispatch(context.Background(), struct{}{},
		call("core.filesystem", `{"operation":"read"}`), sys.Authorization{})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if pending.Status() != sys.StatusYield {
		t.Fatalf("status = %q, want a yield awaiting approval", pending.Status())
	}
	if served.called != 0 {
		t.Fatal("an unapproved call reached the handler")
	}
	if _, err := dispatcher.Dispatch(context.Background(), struct{}{},
		call("core.filesystem", `{"operation":"read"}`), sys.Authorization{Decision: sys.Approved}); err != nil {
		t.Fatalf("approved dispatch: %v", err)
	}
	if served.called != 1 {
		t.Fatal("an approved call did not reach the handler")
	}
}

// The capability a table publishes is its entries projected — same operations,
// same per-case schema and policy — so the menu cannot drift from what is
// dispatchable, and a monitor above the journal can resolve the same case the
// dispatcher will.
func TestCapabilityIsProjectedFromTheEntries(t *testing.T) {
	get := entry("core.memory", "get", &stub{})
	get.Labels = []string{"stored"}
	put := entry("core.memory", "put", &stub{})
	put.Forbid = []string{"untrusted_web"}
	tbl := table(t, "core.memory", []string{"operation"}, get, put)

	published := tbl.Capabilities()[0]
	if len(published.Discriminator) != 1 || published.Discriminator[0] != "operation" {
		t.Fatalf("discriminator = %v, want [operation]", published.Discriminator)
	}
	if len(published.Operations) != 2 {
		t.Fatalf("operations = %+v, want two", published.Operations)
	}
	resolved, ok := published.FindOperation(json.RawMessage(`{"operation":"put"}`))
	if !ok || len(resolved.Forbid) != 1 || resolved.Forbid[0] != "untrusted_web" {
		t.Fatalf("resolved = %+v ok=%v, want put with its forbid set", resolved, ok)
	}
	if _, ok := published.FindOperation(json.RawMessage(`{"operation":"nope"}`)); ok {
		t.Fatal("an undeclared operation must not resolve to policy")
	}
}
