// Package memory provides tenant-scoped shared memory — the filesystem role
// of the OS model (docs/ARCHITECTURE.md, "Shared state"). Sessions are
// execution scope, not data scope: data that outlives and crosses sessions
// lives at the tenant level and is reached only through these journaled
// capabilities, never ambiently. The two kernel laws fix the driver's form:
// determinism — reads travel the journaled syscall path, so replay re-reads
// the recorded value regardless of later mutations; no ambient authority —
// each grant is scoped to a tenant and attenuated to a subtree (chroot
// semantics: guest keys are relative, escapes are rejected), and writes can
// require human approval. Cross-tenant access is impossible by construction.
//
// A third law governs the driver's one effect: the kernel journals an intent
// before a syscall executes, so a crash between intent and completion
// re-drives the dispatch — at-least-once — under the same idempotency key.
// An effectful driver's activity memory makes that window exactly-once
// (Helland, "Life beyond Distributed Transactions"; Stripe-style idempotency
// keys): put remembers the keys it has executed and replays the recorded
// result for a re-seen key instead of writing again. Reads stay keyless.
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
// the process that wrote it — and Get returns them so a later session reads the
// value *as tainted*, not as laundered truth (the memory-poisoning defense).
// Values are versioned (1 on first write, incremented per write) so writers
// can compare-and-set instead of blindly overwriting each other.
//
// Put and Activity together are the store's activity memory: it remembers, per
// tenant, the idempotency keys of puts it has executed and the version each
// recorded, so a crash-re-driven put replays its outcome instead of executing
// twice. Records must live beside the data, never in it — Get and List must
// not surface them (no reserved-prefix leaks; use separate maps or tables).
type Store interface {
	Get(ctx context.Context, tenant, key string) (value json.RawMessage, labels []string, version int64, ok bool, err error)
	// Put writes key if the expectation holds: PutAny overwrites
	// unconditionally, PutAbsent requires the key not to exist, a positive
	// value requires that exact current version. It returns the new version,
	// or ErrConflict when the expectation fails.
	//
	// A non-empty activity key makes the write exactly-once: if the key is
	// already recorded, Put returns the recorded version without touching the
	// value or re-evaluating the expectation; otherwise it records
	// {activity → new version} adjacent to the write — in one transaction
	// where the store can, under the write's own lock otherwise. A failed
	// expectation records nothing: a conflict is a non-effect, safe to
	// re-evaluate. "" bypasses the activity memory (keyless = at-least-once).
	Put(ctx context.Context, tenant, key string, value json.RawMessage, labels []string, expect int64, activity string) (int64, error)
	List(ctx context.Context, tenant, prefix string) (keys []string, err error)
	// Activity reports whether a put under this activity key already executed,
	// and the version it recorded. The handler asks before any gating, so a
	// re-driven, already-performed effect returns its result instead of
	// re-yielding for an approval that was already granted.
	Activity(ctx context.Context, tenant, activity string) (version int64, done bool, err error)
}

// Capability is the name a core.memory grant publishes — the syscall's own name.
// Its operations (get, put, list) are cases of one discriminated ADT, selected
// by the `operation` field in the call args, not separate capability names.
const Capability = "core.memory"

const (
	// PutAny overwrites unconditionally — last writer wins.
	PutAny int64 = -1
	// PutAbsent creates the key and fails with ErrConflict if it exists.
	PutAbsent int64 = 0
)

// ErrConflict is returned by Store.Put when the version expectation fails.
// The handler surfaces it to the guest as errno conflict; the guest re-reads
// and retries — optimistic concurrency across a tenant's sessions.
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
// space. It satisfies builtin.Handler and publishes the single core.memory
// capability; its get/put/list operations are ADT cases selected by the
// `operation` field. Tenant and subtree are host-side grant parameters — the
// guest only ever sees keys relative to its subtree.
type Handler struct {
	// Name is the published capability name (core.memory).
	Name string
	// Store is the durable KV store.
	Store Store
	// Tenant scopes every access. Required.
	Tenant string
	// Subtree chroots the grant inside the tenant's space ("" = whole space).
	// The grant tree does directory permissions: an agent granted "notes"
	// cannot name anything outside notes/.
	Subtree string
	// Operations are the granted cases keyed by operation name (get/put/list);
	// an operation absent here is not granted. Each carries its per-operation
	// approval requirement and data-flow policy.
	Operations map[string]Operation
}

// Operation is one granted memory case's policy: whether it needs human
// approval, the source classes its results carry (Labels), and the labels it
// refuses to let flow in (Taints, the sink guard).
type Operation struct {
	RequireApproval bool
	Labels          []string
	Taints          []string
}

func (h Handler) Handles(name string) bool { return name == h.Name }

func (h Handler) DispatchCall(ctx context.Context, call sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	if h.Store == nil {
		return sys.FailCode(sys.ErrnoInternal, "memory store is not configured"), nil
	}
	if h.Tenant == "" {
		return sys.FailCode(sys.ErrnoInternal, "memory grant has no tenant"), nil
	}
	operation, err := peekOperation(call.Args)
	if err != nil {
		return sys.FailCode(sys.ErrnoInvalidArgs, err.Error()), nil
	}
	op, granted := h.Operations[operation]
	if !granted {
		return sys.FailCode(sys.ErrnoDenied, fmt.Sprintf("memory operation %q is not granted", operation)), nil
	}
	// Sink guard: refuse before any effect if the run has observed a label this
	// operation forbids. Deterministic on replay — the taint is rebuilt from the
	// journal identically, so the same call denies or passes the same way.
	if blocked := sys.BlockedBy(sys.Taint(ctx), op.Taints); len(blocked) > 0 {
		return sys.FailCode(sys.ErrnoDenied, fmt.Sprintf(
			"flow policy: this run has observed %v, which may not flow into memory %q", blocked, operation)), nil
	}
	var result sys.SyscallResult
	switch operation {
	case "get":
		result, err = h.get(ctx, call)
	case "put":
		result, err = h.put(ctx, call, auth, op.RequireApproval)
	case "list":
		result, err = h.list(ctx, call)
	default:
		return sys.FailCode(sys.ErrnoNotFound, "unknown memory operation: "+operation), nil
	}
	if err != nil || result.Status() != sys.StatusResult {
		return result, err
	}
	// Stamp the operation's source labels (unions with any the value already
	// carries, e.g. get's stored provenance).
	return result.WithLabels(op.Labels...), nil
}

// peekOperation reads the ADT discriminator from a memory call's args.
func peekOperation(args json.RawMessage) (string, error) {
	var envelope struct {
		Operation string `json:"operation"`
	}
	if err := json.Unmarshal(args, &envelope); err != nil {
		return "", fmt.Errorf("decode operation: %v", err)
	}
	if envelope.Operation == "" {
		return "", fmt.Errorf("operation is required")
	}
	return envelope.Operation, nil
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
	// reading process's taint, so a value written from a tainted process resurfaces
	// as tainted in every later session.
	return result.WithLabels(labels...), nil
}

func (h Handler) put(ctx context.Context, call sys.Syscall, auth sys.Authorization, requireApproval bool) (sys.SyscallResult, error) {
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
	// Exactly-once across the intent→completion crash window: the kernel
	// journals an intent before the effect executes and re-drives it after a
	// crash, so this put can arrive again under the same idempotency key. A
	// recorded key means the write — and any approval that gated it — already
	// happened: replay the recorded result before the gate, because
	// re-executing would double-apply the write and re-yielding would ask a
	// human to authorize an effect already performed. The key pins the
	// call-hash, so a re-seen key carries these same arguments and the rebuilt
	// response is byte-identical to the first.
	idem, _ := sys.IdempotencyKey(ctx)
	if idem != "" {
		switch version, done, err := h.Store.Activity(ctx, h.Tenant, idem); {
		case err != nil:
			return storeFailure(ctx, err)
		case done:
			return marshalResult(PutResponse{Key: request.Key, Version: version})
		}
	}
	if requireApproval && auth.Decision != sys.Approved {
		return sys.Yield(fmt.Sprintf("Approve writing memory key %q", request.Key)), nil
	}
	expect := PutAny
	if request.IfVersion != nil {
		if *request.IfVersion < 0 {
			return sys.FailCode(sys.ErrnoInvalidArgs, "if_version must be zero or positive"), nil
		}
		expect = *request.IfVersion
	}
	// The written value derives from anything the process has observed (the guest
	// is opaque), so it is stored with the process's taint, handed down by the
	// flow monitor. The idempotency key rides along so the store records the
	// write's activity adjacent to the write itself.
	version, err := h.Store.Put(ctx, h.Tenant, qualified, request.Value, sys.Taint(ctx), expect, idem)
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
// Production supplies a durable implementation. The activity memory is a
// separate map (invisible to Get/List by construction) sharing the store's
// one mutex, so the write and its record are atomic. Being process-local it
// dies with the values themselves — it covers re-drives within one host
// lifetime — and grows unboundedly, which its role affords.
type MapStore struct {
	mu         sync.Mutex
	tenants    map[string]map[string]labelled
	activities map[string]map[string]int64 // tenant → activity key → recorded version
}

type labelled struct {
	value   json.RawMessage
	labels  []string
	version int64
}

func NewMapStore() *MapStore {
	return &MapStore{
		tenants:    make(map[string]map[string]labelled),
		activities: make(map[string]map[string]int64),
	}
}

func (s *MapStore) Get(_ context.Context, tenant, key string) (json.RawMessage, []string, int64, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, ok := s.tenants[tenant][key]
	return append(json.RawMessage(nil), stored.value...), append([]string(nil), stored.labels...), stored.version, ok, nil
}

func (s *MapStore) Put(_ context.Context, tenant, key string, value json.RawMessage, labels []string, expect int64, activity string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if activity != "" {
		if version, done := s.activities[tenant][activity]; done {
			return version, nil // this intent already wrote; replay its outcome
		}
	}
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
	if activity != "" {
		records := s.activities[tenant]
		if records == nil {
			records = make(map[string]int64)
			s.activities[tenant] = records
		}
		records[activity] = next // same mutex hold as the write: atomic
	}
	return next, nil
}

func (s *MapStore) Activity(_ context.Context, tenant, activity string) (int64, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	version, done := s.activities[tenant][activity]
	return version, done, nil
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
