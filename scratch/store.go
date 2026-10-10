// Package scratch is the core.scratch driver: a key-value memory that the
// processes of one session share. Its operations are get, put, store, list and
// search. Every value keeps the labels of the run that wrote it.
//
//	registration.go  a grant's config → the entries
//	handler.go       the operations
//	store.go         the Store interface, and MapStore in memory
//
// Reads go through the journal, so a replay sees the value the first run read,
// whatever changed since. The host binds the handler to one session's space,
// so a guest cannot name another session's keys. The writes (put and store) are
// at least once: a crash between intent and completion runs the write again,
// which is harmless. A session runs one process at a time, so a space has one
// writer.
package scratch

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
)

// Store is one session's space of keys: all the handler can reach. Keys are
// slash-separated paths. Every value is stored with its labels (the taint of
// the run that wrote it), and Get returns them, so a later read inherits the
// taint.
type Store interface {
	Get(ctx context.Context, key string) (value json.RawMessage, labels []string, ok bool, err error)
	// Put writes key, replacing any value it held.
	Put(ctx context.Context, key string, value json.RawMessage, labels []string) error
	// List returns each key under prefix with its value's labels: a key name
	// can carry data too, so listing keys inherits the same taint as reading
	// the values.
	List(ctx context.Context, prefix string) (keys []ListedKey, err error)
}

// ListedKey is a key returned by List together with the provenance labels of its
// stored value.
type ListedKey struct {
	Key    string
	Labels []string
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
