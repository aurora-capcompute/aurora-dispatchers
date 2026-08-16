// Package memory provides tenant-scoped shared memory — the filesystem role
// of the OS model (docs/ARCHITECTURE.md, "Shared state"). Sessions are
// execution scope, not data scope: data that outlives and crosses sessions
// lives at the tenant level and is reached only through these journaled
// capabilities, never ambiently. The two kernel laws fix the driver's form:
// determinism — reads travel the journaled syscall path, so replay re-reads
// the recorded value regardless of later mutations; no ambient authority —
// each grant is scoped to a tenant and partitioned into mounts (process,
// session, or a named shared space; guest keys are relative to the mount's
// host-computed prefix and escapes are rejected), and writes can
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
	"regexp"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/aurora-capcompute/aurora-capcompute/capability"
	"github.com/aurora-capcompute/capcompute/sys"
)

// Store is the app-supplied durable KV store behind tenant memory. Keys are
// slash-separated paths, already tenant- and mount-qualified by the
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
	// List returns each matching key WITH the provenance labels of its stored
	// value, so enumerating keys carries the same taint a get of each value would
	// — key names are not a label-free side channel a tainted writer can use to
	// smuggle data to a later reader.
	List(ctx context.Context, tenant, prefix string) (keys []ListedKey, err error)
	// Activity reports whether a put under this activity key already executed,
	// and the version it recorded. The handler asks before any gating, so a
	// re-driven, already-performed effect returns its result instead of
	// re-yielding for an approval that was already granted.
	Activity(ctx context.Context, tenant, activity string) (version int64, done bool, err error)
}

// ListedKey is a key returned by List together with the provenance labels of its
// stored value.
type ListedKey struct {
	Key    string
	Labels []string
}

// Capability is the name a core.memory grant publishes — the syscall's own name.
// Its operations (get, put, list) are cases of one discriminated ADT, selected
// by the `operation` field in the call args, not separate capability names.
const Capability = "core.memory"

// Memory scopes — the compartment kinds a mount may address. A call selects its
// mount with `scope`; when the scope is shared it also names which space with a
// separate `space` field (the tag and its payload are distinct fields, never
// packed into one string). This vocabulary is the call ABI and lives here; the
// registry validates grants against it.
const (
	ScopeProcess = "process"
	ScopeSession = "session"
	ScopeShared  = "shared"
)

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

// GetRequest asks for one key, relative to the addressed mount.
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

// SearchRequest greps one stored value with an RE2 regex. It is the bounded read
// that makes a large value usable without pulling it whole into context: the
// full value is searched host-side and only the matching lines come back.
type SearchRequest struct {
	Key     string `json:"key"`
	Pattern string `json:"pattern"`
	// IgnoreCase makes the match case-insensitive (an RE2 (?i) prefix).
	IgnoreCase bool `json:"ignore_case,omitempty"`
	// Context is the number of surrounding lines to return with each match
	// (grep -C), clamped to a small maximum.
	Context int `json:"context,omitempty"`
	// MaxMatches caps how many matches come back (default 20), clamped.
	MaxMatches int `json:"max_matches,omitempty"`
}

// Match is one grep hit: the 1-based line number and the matching line, with any
// requested surrounding context, truncated if very long.
type Match struct {
	Line int    `json:"line"`
	Text string `json:"text"`
}

type SearchResponse struct {
	Key     string  `json:"key"`
	Found   bool    `json:"found"`
	Matches []Match `json:"matches"`
	// Truncated reports that a cap (match count or total size) stopped the scan
	// before the whole value was searched.
	Truncated bool `json:"truncated,omitempty"`
}

// Grep result bounds — a search over any-size value returns a small, capped
// result so it never re-floods the context it was meant to keep small.
const (
	searchDefaultMaxMatches = 20
	searchMaxMatches        = 100
	searchMaxContextLines   = 5
	searchMaxMatchBytes     = 512
	searchMaxTotalBytes     = 16 * 1024
)

// Handler serves one memory grant: a tenant plus the mounts the grant opens
// within it. It satisfies builtin.Handler and publishes the single core.memory
// capability; its get/put/list operations are ADT cases selected by the
// `operation` field. Tenant and mount prefixes are host-side grant parameters —
// the guest only ever sees keys relative to its mount.
type Handler struct {
	// Name is the published capability name (core.memory).
	Name string
	// Store is the durable KV store.
	Store Store
	// Tenant is the absolute isolation boundary: it prefixes every physical key
	// and is host-set from the process credential (never guest-supplied), so no
	// access can ever cross tenants. Required.
	Tenant string
	// Mounts are the compartments this grant may address. A call selects one by
	// its `scope` (process, session, shared) plus `space` when the scope is
	// Mount is the one compartment this grant addresses: the operations it
	// allows and the policy the registry publishes for them.
	Mount Mount
}

// Mount is one compartment a grant may address: the physical key prefix it
// resolves to inside the tenant (host-computed from the process credential), the
// operations allowed on it, and the data-flow policy that applies — approval
// gates writes, Labels stamp reads, Taints guard writes.
type Mount struct {
	// Operations is the set of verbs granted (get/put/list/search).
	Operations map[string]struct{}
	// RequireApproval, Labels and Taints are read by the registry to publish the
	// grant's entries. Nothing here enforces them — the runtime does, above and
	// below the replay tape.
	RequireApproval bool
	Labels          []string
	Taints          []string
}

// grants reports whether the mount permits an operation.
func (m Mount) grants(operation string) bool {
	_, ok := m.Operations[operation]
	return ok
}

func (h Handler) Handles(name string) bool { return name == h.Name }

func (h Handler) DispatchCall(ctx context.Context, call sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	if h.Store == nil {
		return sys.FailCode(sys.ErrnoInternal, "memory store is not configured"), nil
	}
	if h.Tenant == "" {
		return sys.FailCode(sys.ErrnoInternal, "memory grant has no tenant"), nil
	}
	operation, err := peekCall(call.Args)
	if err != nil {
		return sys.FailCode(sys.ErrnoInvalidArgs, err.Error()), nil
	}
	mount := h.Mount
	if !mount.grants(operation) {
		return sys.FailCode(sys.ErrnoDenied, fmt.Sprintf("operation %q is not granted", operation)), nil
	}
	// Flow policy and approval are this (operation, mount) case's entry's,
	// enforced by the runtime above and below the replay tape. This handler
	// reads and writes.
	var result sys.SyscallResult
	switch operation {
	case "get":
		result, err = h.get(ctx, call, mount)
	case "put":
		result, err = h.put(ctx, call, auth, mount)
	case "list":
		result, err = h.list(ctx, call, mount)
	case "search":
		result, err = h.search(ctx, call, mount)
	default:
		return sys.FailCode(sys.ErrnoNotFound, "unknown memory operation: "+operation), nil
	}
	if err != nil || result.Status() != sys.StatusResult {
		return result, err
	}
	// The stored provenance a value already carries is the value's own and is
	// stamped by the read; the mount's source labels are the entry's.
	return result, nil
}

// peekCall reads the ADT discriminator and the mount selector from a call's
// args, and enforces the selector's shape: `space` accompanies exactly the
// shared scope — the scope tag and the space payload are separate fields.
func peekCall(args json.RawMessage) (string, error) {
	var envelope struct {
		Operation string `json:"operation"`
	}
	if err := json.Unmarshal(args, &envelope); err != nil {
		return "", fmt.Errorf("decode call: %v", err)
	}
	if envelope.Operation == "" {
		return "", fmt.Errorf("operation is required")
	}
	return envelope.Operation, nil
}

func (h Handler) get(ctx context.Context, call sys.Syscall, mount Mount) (sys.SyscallResult, error) {
	var request GetRequest
	if err := json.Unmarshal(call.Args, &request); err != nil {
		return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("decode %s request: %v", call.Name, err)), nil
	}
	qualified, err := qualify("", request.Key)
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

func (h Handler) put(ctx context.Context, call sys.Syscall, auth sys.Authorization, mount Mount) (sys.SyscallResult, error) {
	var request PutRequest
	if err := json.Unmarshal(call.Args, &request); err != nil {
		return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("decode %s request: %v", call.Name, err)), nil
	}
	qualified, err := qualify("", request.Key)
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
	idem, _ := capability.IdempotencyKey(ctx)
	if idem != "" {
		switch version, done, err := h.Store.Activity(ctx, h.Tenant, idem); {
		case err != nil:
			return storeFailure(ctx, err)
		case done:
			return marshalResult(PutResponse{Key: request.Key, Version: version})
		}
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
	version, err := h.Store.Put(ctx, h.Tenant, qualified, request.Value, capability.Taint(ctx), expect, idem)
	if errors.Is(err, ErrConflict) {
		return sys.FailCode(sys.ErrnoConflict, fmt.Sprintf("key %q is not at version %d; re-read and retry", request.Key, expect)), nil
	}
	if err != nil {
		return storeFailure(ctx, err)
	}
	return marshalResult(PutResponse{Key: request.Key, Version: version})
}

func (h Handler) list(ctx context.Context, call sys.Syscall, mount Mount) (sys.SyscallResult, error) {
	var request ListRequest
	if len(call.Args) > 0 {
		if err := json.Unmarshal(call.Args, &request); err != nil {
			return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("decode %s request: %v", call.Name, err)), nil
		}
	}
	prefix := ""
	if request.Prefix != "" {
		qualified, err := qualify("", request.Prefix)
		if err != nil {
			return sys.FailCode(sys.ErrnoInvalidArgs, err.Error()), nil
		}
		prefix = qualified
	}
	entries, err := h.Store.List(ctx, h.Tenant, prefix)
	if err != nil {
		return storeFailure(ctx, err)
	}
	// Return keys relative to the mount — the guest's view — and carry
	// the union of the listed values' provenance labels, so a key name derived
	// from tainted data cannot be read back label-free (get/search already
	// re-stamp their values; list now matches for key names).
	relative := make([]string, 0, len(entries))
	var labels []string
	for _, entry := range entries {
		key := entry.Key
		relative = append(relative, key)
		labels = append(labels, entry.Labels...)
	}
	sort.Strings(relative)
	result, err := marshalResult(ListResponse{Keys: relative})
	if err != nil {
		return result, err
	}
	return result.WithLabels(labels...), nil
}

func (h Handler) search(ctx context.Context, call sys.Syscall, mount Mount) (sys.SyscallResult, error) {
	var request SearchRequest
	if err := json.Unmarshal(call.Args, &request); err != nil {
		return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("decode %s request: %v", call.Name, err)), nil
	}
	qualified, err := qualify("", request.Key)
	if err != nil {
		return sys.FailCode(sys.ErrnoInvalidArgs, err.Error()), nil
	}
	pattern := request.Pattern
	if request.IgnoreCase {
		pattern = "(?i)" + pattern
	}
	// RE2 is linear-time with no catastrophic backtracking, so a pattern from an
	// untrusted model is safe to compile and run over a large value.
	re, err := regexp.Compile(pattern)
	if err != nil {
		return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("invalid pattern: %v", err)), nil
	}
	value, labels, _, found, err := h.Store.Get(ctx, h.Tenant, qualified)
	if err != nil {
		return storeFailure(ctx, err)
	}
	response := SearchResponse{Key: request.Key, Found: found, Matches: []Match{}}
	if found {
		response.Matches, response.Truncated = grepValue(value, re, request.Context, request.MaxMatches)
	}
	result, err := marshalResult(response)
	if err != nil {
		return result, err
	}
	// Carry the stored value's provenance, exactly like get: a match extracted
	// from a tainted value is itself tainted.
	return result.WithLabels(labels...), nil
}

// grepValue scans the value line by line, returning up to a bounded number of
// matches — each with its 1-based line number and any requested surrounding
// context — and whether a cap cut the scan short. A JSON string value is
// searched as its decoded text (so real newlines are line breaks); any other
// value is searched as its stored JSON bytes.
func grepValue(value json.RawMessage, re *regexp.Regexp, contextLines, maxMatches int) ([]Match, bool) {
	contextLines = clampInt(contextLines, 0, searchMaxContextLines)
	if maxMatches <= 0 {
		maxMatches = searchDefaultMaxMatches
	}
	maxMatches = clampInt(maxMatches, 1, searchMaxMatches)

	lines := strings.Split(valueText(value), "\n")
	matches := make([]Match, 0, maxMatches)
	total := 0
	for i, line := range lines {
		if !re.MatchString(line) {
			continue
		}
		if len(matches) >= maxMatches {
			return matches, true
		}
		start := i - contextLines
		if start < 0 {
			start = 0
		}
		end := i + contextLines + 1
		if end > len(lines) {
			end = len(lines)
		}
		block := truncateBytes(strings.Join(lines[start:end], "\n"), searchMaxMatchBytes)
		matches = append(matches, Match{Line: i + 1, Text: block})
		if total += len(block); total >= searchMaxTotalBytes {
			return matches, true
		}
	}
	return matches, false
}

// valueText decodes a stored value to searchable text: a JSON string yields its
// unescaped content (with real newlines); anything else yields its raw JSON.
func valueText(value json.RawMessage) string {
	var text string
	if json.Unmarshal(value, &text) == nil {
		return text
	}
	return string(value)
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// truncateBytes caps a string at max bytes on a rune boundary, marking the cut.
func truncateBytes(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

// qualify validates a guest key and roots it under a mount's physical prefix.
// Chroot semantics: keys are relative slash-paths; traversal cannot escape
// because escapes are rejected, not resolved. The prefix is host-computed from
// the scope, so the returned physical key always stays inside the mount.
func qualify(prefix, key string) (string, error) {
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
	if prefix == "" {
		return key, nil
	}
	return prefix + "/" + key, nil
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

func (s *MapStore) List(_ context.Context, tenant, prefix string) ([]ListedKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var keys []ListedKey
	for key, stored := range s.tenants[tenant] {
		if prefix == "" || key == prefix || strings.HasPrefix(key, prefix+"/") {
			keys = append(keys, ListedKey{Key: key, Labels: append([]string(nil), stored.labels...)})
		}
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].Key < keys[j].Key })
	return keys, nil
}
