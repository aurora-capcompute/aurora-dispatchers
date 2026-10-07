// Package memory is a labelled, versioned key-value handler over a Store: get,
// put, list and search, each an ADT case selected by `operation`. Its one
// consumer is core.scratch, whose Store is the calling session's durable
// space. The two kernel laws fix the handler's form: determinism — reads travel
// the journaled syscall path, so replay re-reads the recorded value regardless
// of later mutations; no ambient authority — the host hands the handler one
// space, so a guest names keys only inside it.
//
// Its one effect, put, is at-least-once: the kernel journals an intent before a
// syscall executes, so a crash between intent and completion re-drives the
// write. A plain put repeats harmlessly. A compare-and-set put that finds its
// own write already in place reports success instead of a conflict (see put).
package memory

import (
	"bytes"
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

// Store is one space of keys — the whole of what a Handler can reach. The host
// binds it before the handler sees it, so the handler names no session and
// cannot address another space. Keys are slash-separated paths.
// Every value is stored with its provenance labels — the taint of the process
// that wrote it — and Get returns them so a later read sees the value *as
// tainted*, not as laundered truth. Values are versioned (1 on first write,
// incremented per write) so writers can compare-and-set instead of blindly
// overwriting each other.
type Store interface {
	Get(ctx context.Context, key string) (value json.RawMessage, labels []string, version int64, ok bool, err error)
	// Put writes key if the expectation holds: PutAny overwrites
	// unconditionally, PutAbsent requires the key not to exist, a positive
	// value requires that exact current version. It returns the new version,
	// or ErrConflict when the expectation fails.
	Put(ctx context.Context, key string, value json.RawMessage, labels []string, expect int64) (int64, error)
	// List returns each matching key WITH the provenance labels of its stored
	// value, so enumerating keys carries the same taint a get of each value would
	// — key names are not a label-free side channel a tainted writer can use to
	// smuggle data to a later reader.
	List(ctx context.Context, prefix string) (keys []ListedKey, err error)
}

// ListedKey is a key returned by List together with the provenance labels of its
// stored value.
type ListedKey struct {
	Key    string
	Labels []string
}

const (
	// PutAny overwrites unconditionally — last writer wins.
	PutAny int64 = -1
	// PutAbsent creates the key and fails with ErrConflict if it exists.
	PutAbsent int64 = 0
)

// ErrConflict is returned by Store.Put when the version expectation fails.
// The handler surfaces it to the guest as errno conflict; the guest re-reads
// and retries — optimistic concurrency across the processes that share a space.
var ErrConflict = errors.New("memory: version conflict")

// GetRequest asks for one key.
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

// Handler serves get/put/list/search over one Store. Which operations a grant
// opens, their flow policy, and approval are the grant table's entries,
// enforced by the runtime before a call reaches this handler; the handler only
// reads and writes.
type Handler struct {
	// Name is the published capability name.
	Name string
	// Store is the one space the handler serves. A nil Store fails every call
	// with errno internal: the host did not bind a space.
	Store Store
}

func (h Handler) Handles(name string) bool { return name == h.Name }

func (h Handler) DispatchCall(ctx context.Context, call sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	if h.Store == nil {
		return sys.FailCode(sys.ErrnoInternal, "memory store is not configured"), nil
	}
	operation, err := peekCall(call.Args)
	if err != nil {
		return sys.FailCode(sys.ErrnoInvalidArgs, err.Error()), nil
	}
	switch operation {
	case "get":
		return h.get(ctx, call)
	case "put":
		return h.put(ctx, call)
	case "list":
		return h.list(ctx, call)
	case "search":
		return h.search(ctx, call)
	default:
		return sys.FailCode(sys.ErrnoNotFound, "unknown memory operation: "+operation), nil
	}
}

// peekCall reads the ADT discriminator from a call's args.
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

func (h Handler) get(ctx context.Context, call sys.Syscall) (sys.SyscallResult, error) {
	var request GetRequest
	if err := json.Unmarshal(call.Args, &request); err != nil {
		return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("decode %s request: %v", call.Name, err)), nil
	}
	qualified, err := qualify(request.Key)
	if err != nil {
		return sys.FailCode(sys.ErrnoInvalidArgs, err.Error()), nil
	}
	value, labels, version, found, err := h.Store.Get(ctx, qualified)
	if err != nil {
		return storeFailure(ctx, err)
	}
	result, err := marshalResult(GetResponse{Key: request.Key, Found: found, Value: value, Version: version})
	if err != nil {
		return result, err
	}
	// Restamp the stored provenance: the flow monitor accumulates it into the
	// reading process's taint, so a value written from a tainted process resurfaces
	// as tainted in every later process that reads it.
	return result.WithLabels(labels...), nil
}

func (h Handler) put(ctx context.Context, call sys.Syscall) (sys.SyscallResult, error) {
	var request PutRequest
	if err := json.Unmarshal(call.Args, &request); err != nil {
		return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("decode %s request: %v", call.Name, err)), nil
	}
	qualified, err := qualify(request.Key)
	if err != nil {
		return sys.FailCode(sys.ErrnoInvalidArgs, err.Error()), nil
	}
	if len(request.Value) == 0 {
		return sys.FailCode(sys.ErrnoInvalidArgs, "value is required"), nil
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
	// flow monitor.
	version, err := h.Store.Put(ctx, qualified, request.Value, capability.Taint(ctx), expect)
	if errors.Is(err, ErrConflict) {
		// A crash between this put and its completion record re-drives it, and
		// the first run may have written already. If the key now holds exactly
		// this value at the version this put would have made, the state is what
		// the put asked for — whoever wrote it — so the put succeeded.
		current, _, at, found, getErr := h.Store.Get(ctx, qualified)
		if getErr == nil && found && at == expect+1 && bytes.Equal(current, request.Value) {
			return marshalResult(PutResponse{Key: request.Key, Version: at})
		}
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
	prefix := ""
	if request.Prefix != "" {
		qualified, err := qualify(request.Prefix)
		if err != nil {
			return sys.FailCode(sys.ErrnoInvalidArgs, err.Error()), nil
		}
		prefix = qualified
	}
	entries, err := h.Store.List(ctx, prefix)
	if err != nil {
		return storeFailure(ctx, err)
	}
	// Carry the union of the listed values' provenance labels, so a key name
	// derived from tainted data cannot be read back label-free (get/search
	// re-stamp their values; list matches for key names).
	keys := make([]string, 0, len(entries))
	var labels []string
	for _, entry := range entries {
		keys = append(keys, entry.Key)
		labels = append(labels, entry.Labels...)
	}
	sort.Strings(keys)
	result, err := marshalResult(ListResponse{Keys: keys})
	if err != nil {
		return result, err
	}
	return result.WithLabels(labels...), nil
}

func (h Handler) search(ctx context.Context, call sys.Syscall) (sys.SyscallResult, error) {
	var request SearchRequest
	if err := json.Unmarshal(call.Args, &request); err != nil {
		return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("decode %s request: %v", call.Name, err)), nil
	}
	qualified, err := qualify(request.Key)
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
	value, labels, _, found, err := h.Store.Get(ctx, qualified)
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

// qualify validates a guest key: a relative slash-path whose traversal attempts
// are rejected rather than resolved.
func qualify(key string) (string, error) {
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
	return key, nil
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

// MapStore is one space held in memory: the reference Store, and the store
// behind an in-memory deployment. It dies with the host and grows without
// bound, which its role affords.
type MapStore struct {
	mu     sync.Mutex
	values map[string]labelled
}

type labelled struct {
	value   json.RawMessage
	labels  []string
	version int64
}

func NewMapStore() *MapStore {
	return &MapStore{values: make(map[string]labelled)}
}

func (s *MapStore) Get(_ context.Context, key string) (json.RawMessage, []string, int64, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, ok := s.values[key]
	return append(json.RawMessage(nil), stored.value...), append([]string(nil), stored.labels...), stored.version, ok, nil
}

func (s *MapStore) Put(_ context.Context, key string, value json.RawMessage, labels []string, expect int64) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current := s.values[key].version // zero when absent
	if expect != PutAny && expect != current {
		return 0, ErrConflict
	}
	next := current + 1
	s.values[key] = labelled{
		value:   append(json.RawMessage(nil), value...),
		labels:  append([]string(nil), labels...),
		version: next,
	}
	return next, nil
}

func (s *MapStore) List(_ context.Context, prefix string) ([]ListedKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var keys []ListedKey
	for key, stored := range s.values {
		if prefix == "" || key == prefix || strings.HasPrefix(key, prefix+"/") {
			keys = append(keys, ListedKey{Key: key, Labels: append([]string(nil), stored.labels...)})
		}
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].Key < keys[j].Key })
	return keys, nil
}
