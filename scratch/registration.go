package scratch

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/aurora-capcompute/aurora-capcompute/capability"
	"github.com/aurora-capcompute/aurora-dispatchers/registry"
	"github.com/aurora-capcompute/capcompute/sys"
)

// Capability is the syscall/capability name of the session's scratch store.
const Capability = "core.scratch"

// scratchConfig is a core.scratch grant's driver configuration: the operations it
// grants, each an ADT case discriminated by `operation`, with its data-flow
// policy.
type scratchConfig struct {
	Capabilities json.RawMessage `json:"capabilities,omitempty"`
}

// Registration provides core.scratch: a durable KV (get/put/store/list/search) that
// the processes of one session share. A process can leave data for the next
// one — a large fetched page offloaded out of the model's context, notes, an
// auxiliary output — even when the next one sees no session history. The host
// builds one registration per process, over the calling session's Store, so a
// grant never reaches another session's data.
//
// Because scratch is one compartment, its flow policy is a single property of
// the grant: reads carry the union of the granted operations' labels, writes are
// guarded by the union of their taints, and a write requires approval if any
// grant asks for it. In practice a scratch grant declares bare operations and no
// policy at all.
type Registration struct {
	// Store is the calling session's space. It is nil in a config check, which
	// serves no call.
	Store Store
}

func (Registration) Matches(syscall string) bool { return syscall == Capability }

func (r Registration) Configure(_ context.Context, raw json.RawMessage, _ registry.Services) (capability.Family, error) {
	_, grants, err := parseConfig(raw)
	if err != nil {
		return capability.Family{}, err
	}

	requireApproval := false
	var labels, taints []string
	branches := make([]json.RawMessage, 0, len(grants))
	names := make([]string, 0, len(grants))
	for _, grant := range grants {
		if grant.RequireApproval != nil && *grant.RequireApproval {
			requireApproval = true
		}
		labels = registry.UnionLabels(labels, grant.Labels)
		taints = registry.UnionLabels(taints, grant.Taints)
		branch, err := registry.OperationBranch(grant.Operation, operations[grant.Operation].schema)
		if err != nil {
			return capability.Family{}, err
		}
		branches = append(branches, branch)
		names = append(names, operations[grant.Operation].description)
	}

	h := handler{Store: r.Store}
	entries := make([]capability.Entry, 0, len(grants))
	for i, grant := range grants {
		serve := operations[grant.Operation].serve
		entries = append(entries, capability.Entry{
			Key:             capability.Key{Syscall: Capability, Operation: grant.Operation},
			Discriminator:   "operation",
			Description:     operations[grant.Operation].description,
			Input:           branches[i],
			Labels:          labels,
			Forbid:          sinkTaints(grant.Operation, taints),
			RequireApproval: requireApproval && isSink(grant.Operation),
			Handler: capability.HandlerFunc(func(ctx context.Context, call sys.Syscall) (sys.SyscallResult, error) {
				return serve(h, ctx, call)
			}),
		})
	}
	return capability.Family{Entries: entries,
		Description: fmt.Sprintf("Session scratch memory — durable, shared by every process in this session, private to it. Keys are relative slash-paths. Stash large content or notes here for this run or a later one, and query large values with search rather than carrying them in the conversation. Choose an operation:\n- %s.",
			strings.Join(names, "\n- ")),
	}, nil
}

// parseConfig validates and canonicalizes a core.scratch grant — the
// single parse the door check and the build share. It rejects unknown fields,
// requires at least one known operation (get/put/store/list/search) with no
// duplicates, and normalizes each operation's flow policy.
func parseConfig(raw json.RawMessage) (scratchConfig, []registry.OperationGrant, error) {
	var config scratchConfig
	if len(raw) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&config); err != nil {
			return scratchConfig{}, nil, err
		}
	}
	grants, err := registry.ParseOperationGrants(config.Capabilities, "scratch", slices.Sorted(maps.Keys(operations)))
	if err != nil {
		return scratchConfig{}, nil, err
	}
	return config, grants, nil
}

// operations is the operation vocabulary: the argument schema, the
// description, and the handler method of each verb a scratch grant may name.
var operations = map[string]struct {
	schema      json.RawMessage
	description string
	serve       func(handler, context.Context, sys.Syscall) (sys.SyscallResult, error)
}{
	"get": {
		schema:      json.RawMessage(`{"type":"object","properties":{"key":{"type":"string","minLength":1}},"required":["key"],"additionalProperties":false}`),
		description: "get: read one key",
		serve:       handler.get,
	},
	"put": {
		schema:      json.RawMessage(`{"type":"object","properties":{"key":{"type":"string","minLength":1},"value":{}},"required":["key","value"],"additionalProperties":false}`),
		description: "put: write one key, replacing any value it held",
		serve:       handler.put,
	},
	"store": {
		schema:      json.RawMessage(`{"type":"object","properties":{"value":{}},"required":["value"],"additionalProperties":false}`),
		description: "store: save a value under a key made from its content (io/...); a saved value never changes",
		serve:       handler.store,
	},
	"list": {
		schema:      json.RawMessage(`{"type":"object","properties":{"prefix":{"type":"string"}},"additionalProperties":false}`),
		description: "list: list keys under a prefix",
		serve:       handler.list,
	},
	"search": {
		schema:      json.RawMessage(`{"type":"object","properties":{"key":{"type":"string","minLength":1},"pattern":{"type":"string","minLength":1},"ignore_case":{"type":"boolean"},"context":{"type":"integer","minimum":0,"maximum":5},"max_matches":{"type":"integer","minimum":1,"maximum":100}},"required":["key","pattern"],"additionalProperties":false}`),
		description: "search: grep a stored value with an RE2 regex — returns matching lines with line numbers (and optional surrounding context), bounded, so a large value is queried without reading it whole. A value that is not a string is searched as one \"path: value\" line per field, and a long string field as its lines",
		serve:       handler.search,
	},
}

// isSink is true for the operations that write. Only a write is a sink —
// a read is a source — so the grant's forbid set and its approval gate apply to
// those alone.
func isSink(operation string) bool { return operation == "put" || operation == "store" }

// sinkTaints is a grant's forbid set, applied only where it means something.
func sinkTaints(operation string, taints []string) []string {
	if !isSink(operation) {
		return nil
	}
	return taints
}
