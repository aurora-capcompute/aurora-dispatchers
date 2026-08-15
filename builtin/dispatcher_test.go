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

func table(t *testing.T, syscall string, d builtin.Discriminator, entries ...builtin.Entry) *builtin.Table {
	t.Helper()
	tbl := builtin.NewTable()
	if err := tbl.Add(syscall, d, entries, sys.Capability{Name: syscall}); err != nil {
		t.Fatalf("add: %v", err)
	}
	return tbl
}

// The operation in the args selects the entry, and only that entry runs.
func TestDispatchRoutesByOperation(t *testing.T) {
	get, put := &stub{}, &stub{}
	tbl := table(t, "core.memory", builtin.Field("operation"),
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
	tbl := table(t, "core.internet", builtin.Field("method"),
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
	tbl := table(t, "core.memory", builtin.Field("operation"),
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
	tbl := table(t, "core.internet", builtin.Field("method"), entry("core.internet", "GET", served))

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
	tbl := table(t, "core.memory", builtin.Field("operation"), entry("core.memory", "get", &stub{}))

	result, _ := builtin.New[struct{}](tbl).Dispatch(
		context.Background(), struct{}{}, call("core.internet", `{"method":"GET"}`), sys.Authorization{})
	if result.Errno() != sys.ErrnoDenied {
		t.Fatalf("errno = %v, want denied", result.Errno())
	}
}

// Args that carry no readable discriminator are the caller's mistake, reported
// as invalid arguments rather than as a denial.
func TestUnreadableDiscriminatorIsAnArgumentError(t *testing.T) {
	tbl := table(t, "core.memory", builtin.Field("operation"), entry("core.memory", "get", &stub{}))
	dispatcher := builtin.New[struct{}](tbl)

	for _, args := range []string{`{}`, `{"operation":7}`, `"not an object"`} {
		result, err := dispatcher.Dispatch(context.Background(), struct{}{}, call("core.memory", args), sys.Authorization{})
		if err != nil {
			t.Fatalf("dispatch %s: %v", args, err)
		}
		if result.Errno() != sys.ErrnoInvalidArgs {
			t.Fatalf("args %s = %v, want invalid-args", args, result.Errno())
		}
	}
}

// A syscall that is one operation carries no discriminator at all.
func TestSingleOperationSyscall(t *testing.T) {
	served := &stub{}
	tbl := table(t, "sys.log", builtin.SingleOperation, entry("sys.log", "", served))

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
	err := tbl.Add("core.memory", builtin.Field("operation"), []builtin.Entry{
		entry("core.memory", "get", &stub{}),
		entry("core.memory", "get", &stub{}),
	}, sys.Capability{Name: "core.memory"})
	if err == nil || !strings.Contains(err.Error(), "granted twice") {
		t.Fatalf("err = %v, want a duplicate refusal", err)
	}
}

// The same syscall cannot be served by two families.
func TestDuplicateSyscallIsRefused(t *testing.T) {
	tbl := table(t, "core.memory", builtin.Field("operation"), entry("core.memory", "get", &stub{}))
	err := tbl.Add("core.memory", builtin.Field("operation"),
		[]builtin.Entry{entry("core.memory", "put", &stub{})}, sys.Capability{Name: "core.memory"})
	if err == nil || !strings.Contains(err.Error(), "served twice") {
		t.Fatalf("err = %v, want a duplicate-syscall refusal", err)
	}
}

// The index is enumerable — the thing the old capability set could not give,
// since its operations existed only inside a oneOf schema.
func TestEntriesAreEnumerable(t *testing.T) {
	tbl := table(t, "core.memory", builtin.Field("operation"),
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
	tbl := table(t, "core.memory", builtin.Field("operation"), entry("core.memory", "get", served))
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
