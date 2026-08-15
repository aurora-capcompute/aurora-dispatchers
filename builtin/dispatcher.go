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
// the flow and approval policy that applies to it alone, and the thing that
// performs it.
//
// The policy lives here rather than on the Handler because one handler may back
// several entries with different policy — a single internet client serving a
// labelled GET and a forbidding POST — and because it is the entry, not the
// handler, that a monitor above the journal can see.
type Entry struct {
	Key         Key
	Description string
	Input       json.RawMessage
	// Labels are the source classes this operation's results carry; Forbid are
	// the labels barred from flowing into its arguments. Both are published on
	// the capability and enforced by the runtime's monitor — never here.
	Labels []string
	Forbid []string
	// RequireApproval parks the call until a human resolves it. It is enforced
	// here, below the replay tape, so the yield is journaled exactly once.
	RequireApproval bool
	Handler         Handler
}

// discriminator is the argument property whose value names the case. It is read
// by sys.OperationName — the same read the monitor above the journal does, so
// both resolve one call to one case; a divergence there would apply no policy at
// all. Nothing is canonicalized, so a near miss is a refusal naming the
// alternatives rather than a silent correction.
type discriminator string

func (d discriminator) caseName(args json.RawMessage) (string, error) {
	if d == "" {
		return "", nil // a syscall that is one operation
	}
	name, ok := sys.OperationName(string(d), args)
	if !ok {
		return "", fmt.Errorf("arguments must be an object with a string %q", string(d))
	}
	return name, nil
}

// Table is one process's whole leaf surface: every operation it may reach, how
// to find the operation in a call, and the capabilities those operations add up
// to.
// Contribution is everything one family has to say about one syscall: the
// argument properties that name a case, the case it grants, and the capability
// they add up to. A family returns this and touches nothing else — the table is
// the assembler's, so no family can reach past its own grant.
type Contribution struct {
	// Discriminator names the argument property whose value selects a case.
	// Empty means the syscall is one operation.
	Discriminator string
	Entries       []Entry
	Capability    sys.Capability
}

// syscall is the one this contribution is for, taken from the entries rather
// than passed alongside them — there is then no way for the two to disagree.
func (c Contribution) syscall() (string, error) {
	if len(c.Entries) == 0 {
		return "", fmt.Errorf("a contribution must grant at least one operation")
	}
	syscall := c.Entries[0].Key.Syscall
	for _, entry := range c.Entries {
		if entry.Key.Syscall != syscall {
			return "", fmt.Errorf("contribution mixes syscalls %q and %q", syscall, entry.Key.Syscall)
		}
	}
	return syscall, nil
}

type Table struct {
	entries        map[Key]Entry
	discriminators map[string]discriminator
	capabilities   []sys.Capability
}

func NewTable() *Table {
	return &Table{entries: make(map[Key]Entry), discriminators: make(map[string]discriminator)}
}

// Add indexes one family's entries under its discriminator. A duplicate key is
// an error rather than a silent first-wins: two grants serving one operation is
// a manifest that means two things at once, and the old linear scan answered
// that by picking whichever was appended first.
func (t *Table) Add(contribution Contribution) error {
	syscall, err := contribution.syscall()
	if err != nil {
		return err
	}
	if _, taken := t.discriminators[syscall]; taken {
		return fmt.Errorf("syscall %q is served twice", syscall)
	}
	for _, entry := range contribution.Entries {
		if entry.Handler == nil {
			return fmt.Errorf("entry %s has no handler", entry.Key)
		}
		if _, taken := t.entries[entry.Key]; taken {
			return fmt.Errorf("operation %s is granted twice", entry.Key)
		}
		t.entries[entry.Key] = entry
	}
	t.discriminators[syscall] = discriminator(contribution.Discriminator)
	// The capability's ADT is the entries, projected: the operation list, its
	// per-case schema, and its per-case policy all come from one place, so the
	// menu cannot drift from what is dispatchable.
	capability := contribution.Capability
	capability.Discriminator = contribution.Discriminator
	capability.Operations = operationsOf(contribution.Entries)
	t.capabilities = append(t.capabilities, capability)
	return nil
}

// operationsOf projects the indexed entries into the capability's declared
// cases, ordered.
func operationsOf(entries []Entry) []sys.Operation {
	out := make([]sys.Operation, 0, len(entries))
	for _, entry := range entries {
		if entry.Key.Operation == "" {
			continue
		}
		out = append(out, sys.Operation{
			Name:            entry.Key.Operation,
			Description:     entry.Description,
			InputSchema:     entry.Input,
			Labels:          entry.Labels,
			Forbid:          entry.Forbid,
			RequireApproval: entry.RequireApproval,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
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
	names, served := d.table.discriminators[call.Name]
	if !served {
		return sys.FailCode(sys.ErrnoDenied, fmt.Sprintf("capability %q is not granted", call.Name)), nil
	}
	operation, err := names.caseName(call.Args)
	if err != nil {
		return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("%s: %v", call.Name, err)), nil
	}
	entry, granted := d.table.entries[Key{Syscall: call.Name, Operation: operation}]
	if !granted {
		return sys.FailCode(sys.ErrnoDenied, refusal(call.Name, operation, d.table.Operations(call.Name))), nil
	}
	// Approval is enforced here, in one place, below the replay tape: the yield
	// and the human's answer are journaled exactly once, and no driver has to
	// remember to ask.
	if entry.RequireApproval && auth.Decision != sys.Approved {
		return sys.Yield(approvalPrompt(entry, call)), nil
	}
	return entry.Handler.DispatchCall(ctx, call, auth)
}

// approvalPrompt is what a human is asked to approve.
func approvalPrompt(entry Entry, call sys.Syscall) string {
	if entry.Description != "" {
		return fmt.Sprintf("Approve %s: %s", entry.Key, entry.Description)
	}
	return fmt.Sprintf("Approve %s", entry.Key)
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
