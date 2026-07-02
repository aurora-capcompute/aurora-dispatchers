// Package memory provides tenant-scoped shared memory — the filesystem role
// of the OS model (docs/ARCHITECTURE.md, "Shared state"). Sessions are
// execution scope, not data scope: data that outlives and crosses threads
// lives at the tenant level and is reached only through these journaled
// capabilities, never ambiently. The two kernel laws fix the driver's form:
// determinism — reads travel the journaled syscall path, so replay re-reads
// the recorded value regardless of later mutations; no ambient authority —
// each grant is scoped to a tenant and attenuated to a subtree (chroot
// semantics: guest keys are relative, escapes are rejected), and writes can
// require human approval. Cross-tenant access is impossible by construction.
package memory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/aurora-capcompute/capcompute/sys"
)

// Store is the app-supplied durable KV store behind tenant memory. Keys are
// slash-separated paths, already tenant- and subtree-qualified by the
// handler. Every value is stored with its provenance labels — the taint of
// the run that wrote it — and Get returns them so a later thread reads the
// value *as tainted*, not as laundered truth (the memory-poisoning defense).
// Values are versioned (1 on first write, incremented per write) so writers
// can compare-and-set instead of blindly overwriting each other.
type Store interface {
	Get(ctx context.Context, tenant, key string) (value json.RawMessage, labels []string, version int64, ok bool, err error)
	// Put writes key if the expectation holds: PutAny overwrites
	// unconditionally, PutAbsent requires the key not to exist, a positive
	// value requires that exact current version. It returns the new version,
	// or ErrConflict when the expectation fails.
	Put(ctx context.Context, tenant, key string, value json.RawMessage, labels []string, expect int64) (int64, error)
	List(ctx context.Context, tenant, prefix string) (keys []string, err error)
}

// Put expectations.
const (
	// PutAny overwrites unconditionally — last writer wins.
	PutAny int64 = -1
	// PutAbsent creates the key and fails with ErrConflict if it exists.
	PutAbsent int64 = 0
)

// ErrConflict is returned by Store.Put when the version expectation fails.
// The handler surfaces it to the guest as errno conflict; the guest re-reads
// and retries — optimistic concurrency across a tenant's threads.
var ErrConflict = errors.New("memory: version conflict")

// GetRequest asks for one key, relative to the grant's subtree.
type GetRequest struct {
	Key string `json:"key"`
}

type GetResponse struct {
	Key     string          `json:"key"`
	Found   bool            `json:"found"`
	Value   json.RawMessage `json:"value,omitempty"`
	Version int64           `json:"version,omitempty"`
}

// PutRequest writes one key. Without if_version it is last-writer-wins;
// with it, the write is a compare-and-set: 0 means "create, must not exist",
// a positive value means "replace exactly this version". A failed expectation
// returns errno conflict — re-read and retry.
type PutRequest struct {
	Key       string          `json:"key"`
	Value     json.RawMessage `json:"value"`
	IfVersion *int64          `json:"if_version,omitempty"`
}

type PutResponse struct {
	Key     string `json:"key"`
	Version int64  `json:"version"`
}

type ListRequest struct {
	Prefix string `json:"prefix,omitempty"`
}

type ListResponse struct {
	Keys []string `json:"keys"`
}

// Handler serves one memory grant: a tenant plus a subtree of that tenant's
// space. It satisfies builtin.Handler and publishes <name>.get, <name>.put,
// and <name>.list. Tenant and subtree are host-side grant parameters — the
// guest only ever sees keys relative to its subtree.
type Handler struct {
	// Name is the tool's local manifest name; operations are <Name>.get etc.
	Name string
	// Store is the durable KV store.
	Store Store
	// Tenant scopes every access. Required.
	Tenant string
	// Subtree chroots the grant inside the tenant's space ("" = whole space).
	// The grant tree does directory permissions: an agent granted "notes"
	// cannot name anything outside notes/.
	Subtree string
	// RequireApprovalOnPut gates writes behind a human approval task.
	RequireApprovalOnPut bool
}

func (h Handler) Handles(name string) bool {
	return name == h.Name+".get" || name == h.Name+".put" || name == h.Name+".list"
}

func (h Handler) DispatchCall(ctx context.Context, call sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	if h.Store == nil {
		return sys.FailCode(sys.ErrnoInternal, "memory store is not configured"), nil
	}
	if h.Tenant == "" {
		return sys.FailCode(sys.ErrnoInternal, "memory grant has no tenant"), nil
	}
	switch strings.TrimPrefix(call.Name, h.Name+".") {
	case "get":
		return h.get(ctx, call)
	case "put":
		return h.put(ctx, call, auth)
	case "list":
		return h.list(ctx, call)
	default:
		return sys.FailCode(sys.ErrnoNotFound, "unknown memory operation: "+call.Name), nil
	}
}

func (h Handler) get(ctx context.Context, call sys.Syscall) (sys.SyscallResult, error) {
	var request GetRequest
	if err := json.Unmarshal(call.Args, &request); err != nil {
		return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("decode %s request: %v", call.Name, err)), nil
	}
	qualified, err := h.qualify(request.Key)
	if err != nil {
		return sys.FailCode(sys.ErrnoInvalidArgs, err.Error()), nil
	}
	value, labels, version, found, err := h.Store.Get(ctx, h.Tenant, qualified)
	if err != nil {
		return storeFailure(ctx, err)
	}
	result, err := marshalResult(GetResponse{Key: request.Key, Found: found, Value: value, Version: version})
	if err != nil {
		return result, err
	}
	// Restamp the stored provenance: the flow monitor accumulates it into the
	// reading run's taint, so a value written from a tainted run resurfaces
	// as tainted in every later thread.
	return result.WithLabels(labels...), nil
}

func (h Handler) put(ctx context.Context, call sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	var request PutRequest
	if err := json.Unmarshal(call.Args, &request); err != nil {
		return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("decode %s request: %v", call.Name, err)), nil
	}
	qualified, err := h.qualify(request.Key)
	if err != nil {
		return sys.FailCode(sys.ErrnoInvalidArgs, err.Error()), nil
	}
	if len(request.Value) == 0 {
		return sys.FailCode(sys.ErrnoInvalidArgs, "value is required"), nil
	}
	if h.RequireApprovalOnPut && auth.Decision != sys.Approved {
		return sys.Yield(fmt.Sprintf("Approve writing memory key %q", request.Key)), nil
	}
	expect := PutAny
	if request.IfVersion != nil {
		if *request.IfVersion < 0 {
			return sys.FailCode(sys.ErrnoInvalidArgs, "if_version must be zero or positive"), nil
		}
		expect = *request.IfVersion
	}
	// The written value derives from anything the run has observed (the guest
	// is opaque), so it is stored with the run's taint, handed down by the
	// flow monitor.
	version, err := h.Store.Put(ctx, h.Tenant, qualified, request.Value, sys.Taint(ctx), expect)
	if errors.Is(err, ErrConflict) {
		return sys.FailCode(sys.ErrnoConflict, fmt.Sprintf("key %q is not at version %d; re-read and retry", request.Key, expect)), nil
	}
	if err != nil {
		return storeFailure(ctx, err)
	}
	return marshalResult(PutResponse{Key: request.Key, Version: version})
}

func (h Handler) list(ctx context.Context, call sys.Syscall) (sys.SyscallResult, error) {
	var request ListRequest
	if len(call.Args) > 0 {
		if err := json.Unmarshal(call.Args, &request); err != nil {
			return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("decode %s request: %v", call.Name, err)), nil
		}
	}
	prefix := h.Subtree
	if request.Prefix != "" {
		qualified, err := h.qualify(request.Prefix)
		if err != nil {
			return sys.FailCode(sys.ErrnoInvalidArgs, err.Error()), nil
		}
		prefix = qualified
	}
	keys, err := h.Store.List(ctx, h.Tenant, prefix)
	if err != nil {
		return storeFailure(ctx, err)
	}
	// Return keys relative to the grant's subtree — the guest's view.
	relative := make([]string, 0, len(keys))
	for _, key := range keys {
		if h.Subtree != "" {
			key = strings.TrimPrefix(strings.TrimPrefix(key, h.Subtree), "/")
		}
		relative = append(relative, key)
	}
	sort.Strings(relative)
	return marshalResult(ListResponse{Keys: relative})
}

// qualify validates a guest key and roots it under the grant's subtree.
// Chroot semantics: keys are relative slash-paths; traversal cannot escape
// because escapes are rejected, not resolved.
func (h Handler) qualify(key string) (string, error) {
	if key == "" {
		return "", fmt.Errorf("key is required")
	}
	if strings.HasPrefix(key, "/") {
		return "", fmt.Errorf("key %q must be relative", key)
	}
	for _, segment := range strings.Split(key, "/") {
		switch segment {
		case "", ".", "..":
			return "", fmt.Errorf("key %q contains an invalid path segment", key)
		}
	}
	if h.Subtree == "" {
		return key, nil
	}
	return h.Subtree + "/" + key, nil
}

func storeFailure(ctx context.Context, err error) (sys.SyscallResult, error) {
	if ctx.Err() != nil {
		return sys.SyscallResult{}, ctx.Err()
	}
	return sys.FailCode(sys.ErrnoTransient, err.Error()), nil
}

func marshalResult(value any) (sys.SyscallResult, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return sys.SyscallResult{}, err
	}
	return sys.Result(raw), nil
}

// MapStore is the in-memory reference Store — for tests and prototyping.
// Production supplies a durable implementation.
type MapStore struct {
	mu      sync.Mutex
	tenants map[string]map[string]labelled
}

type labelled struct {
	value   json.RawMessage
	labels  []string
	version int64
}

func NewMapStore() *MapStore {
	return &MapStore{tenants: make(map[string]map[string]labelled)}
}

func (s *MapStore) Get(_ context.Context, tenant, key string) (json.RawMessage, []string, int64, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, ok := s.tenants[tenant][key]
	return append(json.RawMessage(nil), stored.value...), append([]string(nil), stored.labels...), stored.version, ok, nil
}

func (s *MapStore) Put(_ context.Context, tenant, key string, value json.RawMessage, labels []string, expect int64) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	space := s.tenants[tenant]
	if space == nil {
		space = make(map[string]labelled)
		s.tenants[tenant] = space
	}
	current := space[key].version // zero when absent
	if expect != PutAny && expect != current {
		return 0, ErrConflict
	}
	next := current + 1
	space[key] = labelled{
		value:   append(json.RawMessage(nil), value...),
		labels:  append([]string(nil), labels...),
		version: next,
	}
	return next, nil
}

func (s *MapStore) List(_ context.Context, tenant, prefix string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var keys []string
	for key := range s.tenants[tenant] {
		if prefix == "" || key == prefix || strings.HasPrefix(key, prefix+"/") {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys, nil
}
