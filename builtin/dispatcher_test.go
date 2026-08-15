package builtin_test

import (
	"context"
	"testing"

	"github.com/aurora-capcompute/aurora-dispatchers/builtin"
	"github.com/aurora-capcompute/capcompute/sys"
)

// stub is a handler that answers to exactly one name and records being reached.
type stub struct {
	name   string
	called bool
}

func (s *stub) Handles(name string) bool { return name == s.name }

func (s *stub) DispatchCall(context.Context, sys.Syscall, sys.Authorization) (sys.SyscallResult, error) {
	s.called = true
	return sys.Result([]byte(`"served"`)), nil
}

func call(name string) sys.Syscall {
	return sys.Syscall{Abi: sys.ABIVersion, Name: name}
}

// Routing is by name, and only the owner is reached.
func TestDispatchReachesTheOwningHandler(t *testing.T) {
	first := &stub{name: "core.memory"}
	second := &stub{name: "core.internet"}
	dispatcher := builtin.New[struct{}](builtin.Config{Handlers: []builtin.Handler{first, second}})

	result, err := dispatcher.Dispatch(context.Background(), struct{}{}, call("core.internet"), sys.Authorization{})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if result.Status() != sys.StatusResult {
		t.Fatalf("status = %s, want a result", result.Status())
	}
	if first.called {
		t.Fatal("a handler that does not own the name was reached")
	}
	if !second.called {
		t.Fatal("the owning handler was never reached")
	}
}

// A name no handler owns fails closed rather than falling through to anything.
func TestDispatchRefusesAnUnservedName(t *testing.T) {
	only := &stub{name: "core.memory"}
	dispatcher := builtin.New[struct{}](builtin.Config{Handlers: []builtin.Handler{only}})

	result, err := dispatcher.Dispatch(context.Background(), struct{}{}, call("core.internet"), sys.Authorization{})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if result.Status() != sys.StatusFailed || result.Errno() != sys.ErrnoNotFound {
		t.Fatalf("result = %#v, want failed/ErrnoNotFound", result)
	}
	if only.called {
		t.Fatal("an unrelated handler was reached")
	}
}

// The advertised capability set is what the runtime's Validator admits, so it
// passes through untouched.
func TestCapabilitiesArePublishedVerbatim(t *testing.T) {
	published := []sys.Capability{{Name: "core.memory"}, {Name: "core.internet"}}
	dispatcher := builtin.New[struct{}](builtin.Config{Capabilities: published})

	got := dispatcher.Capabilities()
	if len(got) != len(published) {
		t.Fatalf("capabilities = %v, want %v", got, published)
	}
	for i := range got {
		if got[i].Name != published[i].Name {
			t.Fatalf("capability %d = %q, want %q", i, got[i].Name, published[i].Name)
		}
	}
}
