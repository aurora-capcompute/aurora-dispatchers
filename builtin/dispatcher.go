// Package builtin routes one process's leaf syscalls to the operation that
// serves them. It is the bottom of the dispatcher chain and knows nothing about
// any particular capability: a family contributes entries keyed by (syscall,
// operation) plus a way to read that operation out of a call's arguments, and
// this package indexes them.
//
// Routing is a map lookup, not a scan, so two grants cannot quietly serve the
// same operation — the fold that builds the table refuses a duplicate key
// instead of letting the first one win.
package builtin

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/aurora-capcompute/capcompute/sys"
)

// Key indexes one operation of one syscall family. Operation is empty for a
// syscall that has no ADT discriminator — it is one operation by itself.
type Key struct {
	Syscall   string
	Operation string
}

func (k Key) String() string {
	if k.Operation == "" {
		return k.Syscall
	}
	return k.Syscall + "/" + k.Operation
}

// Handler performs one operation's effect. It is reached only after the table
// has resolved a call to an entry, so it never routes: one handler may back
// several entries (a single internet client serving GET and POST), and the
// entry — not the handler — is what the call was matched against.
type Handler interface {
	DispatchCall(ctx context.Context, call sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error)
}

// Entry is one dispatchable operation: what it is, the shape of its arguments,
// and the thing that performs it.
type Entry struct {
	Key         Key
	Description string
	Input       json.RawMessage
	Output      json.RawMessage
	Handler     Handler
}

// Discriminator reads the operation out of a call's arguments. It belongs to
// the family that defines the syscall — core.internet reads `method`,
// core.command reads `name`, the rest read `operation` — and returns an empty
// string for a syscall that has none. It does not canonicalize: what it returns
// is matched exactly against the table, so what the guest sent is what is
// looked up, and a near miss is a refusal that names the alternatives rather
// than a silent correction.
type Discriminator func(args json.RawMessage) (string, error)

// SingleOperation is the Discriminator of a syscall that is one operation.
func SingleOperation(json.RawMessage) (string, error) { return "", nil }

// Field builds the Discriminator that reads one top-level string property.
func Field(name string) Discriminator {
	return func(args json.RawMessage) (string, error) {
		var envelope map[string]json.RawMessage
		if err := json.Unmarshal(args, &envelope); err != nil {
			return "", fmt.Errorf("arguments must be an object")
		}
		raw, ok := envelope[name]
		if !ok {
			return "", fmt.Errorf("%q is required", name)
		}
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return "", fmt.Errorf("%q must be a string", name)
		}
		return value, nil
	}
}

// Table is one process's whole leaf surface: every operation it may reach, how
// to find the operation in a call, and the capabilities those operations add up
// to.
type Table struct {
	entries        map[Key]Entry
	discriminators map[string]Discriminator
	capabilities   []sys.Capability
}

func NewTable() *Table {
	return &Table{entries: make(map[Key]Entry), discriminators: make(map[string]Discriminator)}
}

// Add indexes one family's entries under its discriminator. A duplicate key is
// an error rather than a silent first-wins: two grants serving one operation is
// a manifest that means two things at once, and the old linear scan answered
// that by picking whichever was appended first.
func (t *Table) Add(syscall string, discriminator Discriminator, entries []Entry, capability sys.Capability) error {
	if _, taken := t.discriminators[syscall]; taken {
		return fmt.Errorf("syscall %q is served twice", syscall)
	}
	if discriminator == nil {
		return fmt.Errorf("syscall %q has no discriminator", syscall)
	}
	for _, entry := range entries {
		if entry.Key.Syscall != syscall {
			return fmt.Errorf("entry %s does not belong to syscall %q", entry.Key, syscall)
		}
		if entry.Handler == nil {
			return fmt.Errorf("entry %s has no handler", entry.Key)
		}
		if _, taken := t.entries[entry.Key]; taken {
			return fmt.Errorf("operation %s is granted twice", entry.Key)
		}
		t.entries[entry.Key] = entry
	}
	t.discriminators[syscall] = discriminator
	t.capabilities = append(t.capabilities, capability)
	return nil
}

// Hide keeps a syscall's capability dispatchable but off the discoverable menu.
func (t *Table) Hide(syscall string) {
	for i := range t.capabilities {
		if t.capabilities[i].Name == syscall {
			t.capabilities[i].Hidden = true
		}
	}
}

// Operations lists the operations granted for one syscall — what a refusal owes
// the caller.
func (t *Table) Operations(syscall string) []string {
	out := make([]string, 0, len(t.entries))
	for key := range t.entries {
		if key.Syscall == syscall && key.Operation != "" {
			out = append(out, key.Operation)
		}
	}
	sort.Strings(out)
	return out
}

// Capabilities is what the operations add up to: one per served syscall, the
// descriptive projection the runtime's Validator admits and the guest sees.
func (t *Table) Capabilities() []sys.Capability {
	return t.capabilities
}

// Entries returns every indexed operation, ordered — the enumerable surface the
// old capability set could not give, since its operations only existed inside a
// oneOf schema.
func (t *Table) Entries() []Entry {
	out := make([]Entry, 0, len(t.entries))
	for _, entry := range t.entries {
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key.String() < out[j].Key.String() })
	return out
}

type Dispatcher[K any] struct {
	table *Table
}

func New[K any](table *Table) sys.Dispatcher[K] {
	return &Dispatcher[K]{table: table}
}

func (d *Dispatcher[K]) Capabilities() []sys.Capability {
	return d.table.Capabilities()
}

// Dispatch resolves a call to exactly one entry: the family's discriminator
// reads the operation out of the arguments, and the pair indexes the table. A
// miss is a denial rather than a routing failure — the table is the grant.
func (d *Dispatcher[K]) Dispatch(ctx context.Context, _ K, call sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	discriminator, served := d.table.discriminators[call.Name]
	if !served {
		return sys.FailCode(sys.ErrnoDenied, fmt.Sprintf("capability %q is not granted", call.Name)), nil
	}
	operation, err := discriminator(call.Args)
	if err != nil {
		return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("%s: %v", call.Name, err)), nil
	}
	entry, granted := d.table.entries[Key{Syscall: call.Name, Operation: operation}]
	if !granted {
		return sys.FailCode(sys.ErrnoDenied, refusal(call.Name, operation, d.table.Operations(call.Name))), nil
	}
	return entry.Handler.DispatchCall(ctx, call, auth)
}

// refusal names what was asked for and what is available, so a caller can tell a
// typo from a missing grant without reading the manifest back.
func refusal(syscall, operation string, granted []string) string {
	if operation == "" {
		return fmt.Sprintf("capability %q is not granted", syscall)
	}
	if len(granted) == 0 {
		return fmt.Sprintf("%q grants no operations", syscall)
	}
	return fmt.Sprintf("operation %q is not granted on %q; granted: %s",
		operation, syscall, strings.Join(granted, ", "))
}
