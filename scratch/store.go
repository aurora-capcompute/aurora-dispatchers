// Package scratch provides core.scratch: a labelled key-value
// handler over one session's Store — get, put, store, list and search, each an
// ADT case selected by `operation` — and the registration that grants it. The two
// kernel laws fix the handler's form: determinism — reads travel
// the journaled syscall path, so replay re-reads the recorded value regardless
// of later mutations; no ambient authority — the host hands the handler one
// space, so a guest names keys only inside it.
//
// Its effects, put and store, are at-least-once: the kernel journals an intent
// before a syscall executes, so a crash between intent and completion re-drives
// the write, which repeats harmlessly. A session runs one process at a time, so
// a space has one writer.
package scratch

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/aurora-capcompute/aurora-capcompute/capability"
	"github.com/aurora-capcompute/aurora-dispatchers/registry"
	"github.com/aurora-capcompute/capcompute/sys"
)

// Store is one space of keys — the whole of what the handler can reach. The host
// binds it before the handler sees it, so the handler names no session and
// cannot address another space. Keys are slash-separated paths.
// Every value is stored with its provenance labels — the taint of the process
// that wrote it — and Get returns them so a later read sees the value *as
// tainted*, not as laundered truth.
type Store interface {
	Get(ctx context.Context, key string) (value json.RawMessage, labels []string, ok bool, err error)
	// Put writes key, replacing any value it held.
	Put(ctx context.Context, key string, value json.RawMessage, labels []string) error
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

// GetRequest asks for one key.
type GetRequest struct {
	Key string `json:"key"`
}

type GetResponse struct {
	Key   string          `json:"key"`
	Found bool            `json:"found"`
	Value json.RawMessage `json:"value,omitempty"`
}

// PutRequest writes one key, replacing any value it held.
type PutRequest struct {
	Key   string          `json:"key"`
	Value json.RawMessage `json:"value"`
}

type PutResponse struct {
	Key string `json:"key"`
}

// savedPrefix holds the values store saved. Each key is made from its value's
// content, and put may not write under it, so a saved value never changes.
const savedPrefix = "io/"

// StoreRequest saves one value under a key made from its content.
type StoreRequest struct {
	Value json.RawMessage `json:"value"`
}

type StoreResponse struct {
	Key string `json:"key"`
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
	// (grep -C). The schema bounds it.
	Context int `json:"context,omitempty"`
	// MaxMatches caps how many matches come back (default 20). The schema
	// bounds it.
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
	searchMaxMatchBytes     = 512
	searchMaxTotalBytes     = 16 * 1024
)

// handler serves get/put/list/search over one Store. Which operations a grant
// opens, their flow policy, and approval are the grant table's entries,
// enforced by the runtime before a call reaches this handler; the handler only
// reads and writes.
type handler struct {
	// Store is the one space the handler serves.
	Store Store
}

func (h handler) get(ctx context.Context, call sys.Syscall) (sys.SyscallResult, error) {
	var request GetRequest
	if err := json.Unmarshal(call.Args, &request); err != nil {
		return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("decode %s request: %v", call.Name, err)), nil
	}
	if err := checkKey(request.Key); err != nil {
		return sys.FailCode(sys.ErrnoInvalidArgs, err.Error()), nil
	}
	value, labels, found, err := h.Store.Get(ctx, request.Key)
	if err != nil {
		return storeFailure(ctx, err)
	}
	result, err := marshalResult(GetResponse{Key: request.Key, Found: found, Value: value})
	if err != nil {
		return result, err
	}
	// Restamp the stored provenance: the flow monitor accumulates it into the
	// reading process's taint, so a value written from a tainted process resurfaces
	// as tainted in every later process that reads it.
	return result.WithLabels(labels...), nil
}

func (h handler) put(ctx context.Context, call sys.Syscall) (sys.SyscallResult, error) {
	var request PutRequest
	if err := json.Unmarshal(call.Args, &request); err != nil {
		return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("decode %s request: %v", call.Name, err)), nil
	}
	if err := checkKey(request.Key); err != nil {
		return sys.FailCode(sys.ErrnoInvalidArgs, err.Error()), nil
	}
	if strings.HasPrefix(request.Key, savedPrefix) {
		return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("keys under %s hold saved values, which never change", savedPrefix)), nil
	}
	// The written value derives from anything the process has observed (the guest
	// is opaque), so it is stored with the process's taint, handed down by the
	// flow monitor.
	if err := h.Store.Put(ctx, request.Key, request.Value, capability.Taint(ctx)); err != nil {
		return storeFailure(ctx, err)
	}
	return marshalResult(PutResponse{Key: request.Key})
}

// store saves a value under io/<hash of its compact JSON>. The same content
// always gets the same key, so a re-driven store lands where the first one did.
// Saving content that is already there adds the writer's taint to the labels
// the value carries.
func (h handler) store(ctx context.Context, call sys.Syscall) (sys.SyscallResult, error) {
	var request StoreRequest
	if err := json.Unmarshal(call.Args, &request); err != nil {
		return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("decode %s request: %v", call.Name, err)), nil
	}
	// The value decoded as JSON, so it compacts.
	var value bytes.Buffer
	_ = json.Compact(&value, request.Value)
	sum := sha256.Sum256(value.Bytes())
	key := savedPrefix + hex.EncodeToString(sum[:8])
	_, saved, _, err := h.Store.Get(ctx, key)
	if err != nil {
		return storeFailure(ctx, err)
	}
	if err := h.Store.Put(ctx, key, value.Bytes(), registry.UnionLabels(saved, capability.Taint(ctx))); err != nil {
		return storeFailure(ctx, err)
	}
	return marshalResult(StoreResponse{Key: key})
}

func (h handler) list(ctx context.Context, call sys.Syscall) (sys.SyscallResult, error) {
	var request ListRequest
	if err := json.Unmarshal(call.Args, &request); err != nil {
		return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("decode %s request: %v", call.Name, err)), nil
	}
	if request.Prefix != "" {
		if err := checkKey(request.Prefix); err != nil {
			return sys.FailCode(sys.ErrnoInvalidArgs, err.Error()), nil
		}
	}
	entries, err := h.Store.List(ctx, request.Prefix)
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
	slices.Sort(keys)
	result, err := marshalResult(ListResponse{Keys: keys})
	if err != nil {
		return result, err
	}
	return result.WithLabels(labels...), nil
}

func (h handler) search(ctx context.Context, call sys.Syscall) (sys.SyscallResult, error) {
	var request SearchRequest
	if err := json.Unmarshal(call.Args, &request); err != nil {
		return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("decode %s request: %v", call.Name, err)), nil
	}
	if err := checkKey(request.Key); err != nil {
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
	value, labels, found, err := h.Store.Get(ctx, request.Key)
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

// grepValue scans the value line by line, returning up to maxMatches matches —
// each with its 1-based line number and any requested surrounding context — and
// whether a cap cut the scan short. The lines are valueText's.
func grepValue(value json.RawMessage, re *regexp.Regexp, contextLines, maxMatches int) ([]Match, bool) {
	if maxMatches == 0 {
		maxMatches = searchDefaultMaxMatches
	}

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
		start := max(i-contextLines, 0)
		end := min(i+contextLines+1, len(lines))
		block := truncateBytes(strings.Join(lines[start:end], "\n"), searchMaxMatchBytes)
		matches = append(matches, Match{Line: i + 1, Text: block})
		if total += len(block); total >= searchMaxTotalBytes {
			return matches, true
		}
	}
	return matches, false
}

// valueText is the text search reads. A JSON string is its decoded text, so
// real newlines are line breaks. Any other value is flattened to one
// "path: value" line per field, in key order, and a string field gives one line
// per line of it: a long text inside a saved result is searched line by line,
// and each hit says which field it is in.
func valueText(value json.RawMessage) string {
	var text string
	if json.Unmarshal(value, &text) == nil {
		return text
	}
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.UseNumber()
	var decoded any
	if decoder.Decode(&decoded) != nil {
		return string(value)
	}
	var lines []string
	flatten("", decoded, &lines)
	return strings.Join(lines, "\n")
}

func flatten(path string, value any, lines *[]string) {
	line := func(text string) {
		if path != "" {
			text = path + ": " + text
		}
		*lines = append(*lines, text)
	}
	switch v := value.(type) {
	case map[string]any:
		if len(v) == 0 {
			line("{}")
		}
		for _, key := range slices.Sorted(maps.Keys(v)) {
			field := key
			if path != "" {
				field = path + "." + key
			}
			flatten(field, v[key], lines)
		}
	case []any:
		if len(v) == 0 {
			line("[]")
		}
		for i, item := range v {
			flatten(fmt.Sprintf("%s[%d]", path, i), item, lines)
		}
	case string:
		for _, text := range strings.Split(v, "\n") {
			line(text)
		}
	default:
		raw, _ := json.Marshal(v)
		line(string(raw))
	}
}

// truncateBytes caps a string at limit bytes on a rune boundary, marking the cut.
func truncateBytes(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

// checkKey refuses a guest key that is not a relative slash-path: traversal
// attempts are rejected rather than resolved.
func checkKey(key string) error {
	if strings.HasPrefix(key, "/") {
		return fmt.Errorf("key %q must be relative", key)
	}
	for _, segment := range strings.Split(key, "/") {
		switch segment {
		case "", ".", "..":
			return fmt.Errorf("key %q contains an invalid path segment", key)
		}
	}
	return nil
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
	value  json.RawMessage
	labels []string
}

func NewMapStore() *MapStore {
	return &MapStore{values: make(map[string]labelled)}
}

func (s *MapStore) Get(_ context.Context, key string) (json.RawMessage, []string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, ok := s.values[key]
	return append(json.RawMessage(nil), stored.value...), append([]string(nil), stored.labels...), ok, nil
}

func (s *MapStore) Put(_ context.Context, key string, value json.RawMessage, labels []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.values[key] = labelled{
		value:  append(json.RawMessage(nil), value...),
		labels: append([]string(nil), labels...),
	}
	return nil
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
	return keys, nil
}
