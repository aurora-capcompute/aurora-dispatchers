package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/aurora-capcompute/aurora-capcompute/capability"
	"github.com/aurora-capcompute/aurora-dispatchers/memory"
)

// ScratchCapability is the syscall/capability name of the process-scoped scratch
// store.
const ScratchCapability = "core.scratch"

// scratchTenant namespaces keys inside a process's scratch map. Every process
// gets its own fresh store, so isolation comes from the per-process store, not
// the tenant — the tenant is a constant.
const scratchTenant = "scratch"

// scratchConfig is a core.scratch grant's driver configuration: the operations it
// grants, each an ADT case discriminated by `operation`, with its data-flow
// policy. Unlike core.memory there is no scope selector — scratch is a single,
// process-private, unscoped store — so it keeps the plain operation-list shape.
type scratchConfig struct {
	Capabilities json.RawMessage `json:"capabilities,omitempty"`
}

// ScratchRegistration provides core.scratch: a process-local, ephemeral KV with
// the same get/put/list/search operations (and ADT shape) as core.memory, but
// backed by a fresh in-memory store built per process and discarded when the
// process ends. It is the right home for large transient content — a fetched
// page offloaded out of the model's context: private to the process, never
// written to the durable tenant store, and gone when the run is over. The store
// lives for one activation; a process that parks and reactivates starts with an
// empty scratch (the journaled summary/excerpt of any offload survive
// regardless — only a full-text re-query would miss and prompt a re-fetch).
//
// Because scratch is one compartment, its flow policy is a single mount property:
// reads carry the union of the granted operations' labels, writes are guarded by
// the union of their taints, and a write requires approval if any grant asks for
// it. In practice a scratch grant declares bare operations and no policy at all.
type ScratchRegistration struct{}

func (ScratchRegistration) Matches(syscall string) bool { return syscall == ScratchCapability }

func (ScratchRegistration) Configure(_ context.Context, raw json.RawMessage, _ Services) (capability.Family, error) {
	_, grants, err := parseScratchConfig(raw)
	if err != nil {
		return capability.Family{}, err
	}

	ops := make(map[string]struct{}, len(grants))
	requireApproval := false
	var labels, taints []string
	branches := make([]json.RawMessage, 0, len(grants))
	names := make([]string, 0, len(grants))
	for _, grant := range grants {
		ops[grant.Operation] = struct{}{}
		if grant.RequireApproval != nil && *grant.RequireApproval {
			requireApproval = true
		}
		labels = unionLabels(labels, grant.Labels)
		taints = unionLabels(taints, grant.Taints)
		branch, err := OperationBranch(grant.Operation, scratchOperations[grant.Operation].schema)
		if err != nil {
			return capability.Family{}, err
		}
		branches = append(branches, branch)
		names = append(names, scratchOperations[grant.Operation].description)
	}

	// A fresh in-memory store per Configure call — i.e. per process. It is never
	// the durable tenant store (Services is unused here), and it is dropped with
	// the process's dispatcher chain, so nothing stored here outlives the run.
	// Scratch is inherently one compartment — the process's own ephemeral store —
	// so its lone mount is anonymous (no scope, empty prefix = the whole
	// per-process store) and calls address it with no selector.
	handler := memory.Handler{
		Name:   ScratchCapability,
		Store:  memory.NewMapStore(),
		Tenant: scratchTenant,
		Mount: memory.Mount{
			Operations:      ops,
			RequireApproval: requireApproval,
			Labels:          labels,
			Taints:          taints,
		},
	}
	// Scratch is one anonymous mount, so a case is the operation with an empty
	// selector — the same shape core.memory uses, with nothing to disambiguate.
	entries := make([]capability.Entry, 0, len(grants))
	for i, grant := range grants {
		entries = append(entries, capability.Entry{
			Key:             capability.Key{Syscall: ScratchCapability, Operation: grant.Operation},
			Discriminator:   "operation",
			Description:     scratchOperations[grant.Operation].description,
			Input:           branches[i],
			Labels:          labels,
			Forbid:          sinkTaints(grant.Operation, taints),
			RequireApproval: requireApproval && isScratchSink(grant.Operation),
			Handler:         handler,
		})
	}
	return capability.Family{Entries: entries,
		Description: fmt.Sprintf("Process-local scratch memory — ephemeral and private to this process, cleared when it ends, never written to shared storage. Keys are relative slash-paths. Stash large content here and query it with search rather than carrying it in the conversation. Choose an operation:\n- %s.",
			strings.Join(names, "\n- ")),
		Input: OneOfSchema(branches),
	}, nil
}

// parseScratchConfig validates and canonicalizes a core.scratch grant — the
// single parse Normalize and Configure share. It rejects unknown fields, requires
// at least one known operation (get/put/list/search) with no duplicates, and
// normalizes each operation's flow policy. It mirrors the filesystem parser's
// shape; scratch reuses core.memory's operation schemas.
func parseScratchConfig(raw json.RawMessage) (scratchConfig, []OperationGrant, error) {
	var config scratchConfig
	if len(raw) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&config); err != nil {
			return scratchConfig{}, nil, err
		}
	}
	grants, err := DecodeOperationGrants(config.Capabilities)
	if err != nil {
		return scratchConfig{}, nil, err
	}
	if len(grants) == 0 {
		return scratchConfig{}, nil, errors.New("capabilities must grant at least one operation (get, put, list, search)")
	}
	seen := make(map[string]struct{}, len(grants))
	for i := range grants {
		operation := strings.TrimSpace(grants[i].Operation)
		if _, ok := scratchOperations[operation]; !ok {
			return scratchConfig{}, nil, fmt.Errorf("unknown scratch operation %q (want get, put, list, search)", grants[i].Operation)
		}
		if _, dup := seen[operation]; dup {
			return scratchConfig{}, nil, fmt.Errorf("duplicate scratch operation %q", operation)
		}
		seen[operation] = struct{}{}
		grants[i].Operation = operation
		if grants[i].FlowPolicy, err = grants[i].FlowPolicy.Normalized(); err != nil {
			return scratchConfig{}, nil, fmt.Errorf("operation %q: %w", operation, err)
		}
	}
	sortOperationGrants(grants)
	return config, grants, nil
}

// scratchOperations is the operation vocabulary: the argument schema and the
// description of each verb a scratch grant may name.
var scratchOperations = map[string]struct {
	schema      json.RawMessage
	description string
}{
	"get": {
		schema:      json.RawMessage(`{"type":"object","properties":{"key":{"type":"string","minLength":1}},"required":["key"],"additionalProperties":false}`),
		description: "get: read one key (the response carries its version for compare-and-set writes)",
	},
	"put": {
		schema:      json.RawMessage(`{"type":"object","properties":{"key":{"type":"string","minLength":1},"value":{},"if_version":{"type":"integer","minimum":0}},"required":["key","value"],"additionalProperties":false}`),
		description: "put: write one key (optional if_version makes it a compare-and-set: 0 = create only, N = replace exactly version N)",
	},
	"list": {
		schema:      json.RawMessage(`{"type":"object","properties":{"prefix":{"type":"string"}},"additionalProperties":false}`),
		description: "list: list keys under a prefix",
	},
	"search": {
		schema:      json.RawMessage(`{"type":"object","properties":{"key":{"type":"string","minLength":1},"pattern":{"type":"string","minLength":1},"ignore_case":{"type":"boolean"},"context":{"type":"integer","minimum":0,"maximum":5},"max_matches":{"type":"integer","minimum":1,"maximum":100}},"required":["key","pattern"],"additionalProperties":false}`),
		description: "search: grep a stored value with an RE2 regex — returns matching lines with line numbers (and optional surrounding context), bounded, so a large value is queried without reading it whole",
	},
}

// isScratchSink is true for the operations that write. Only a write is a sink —
// a read is a source — so the grant's forbid set and its approval gate apply to
// those alone.
func isScratchSink(operation string) bool { return operation == "put" }

// sinkTaints is a grant's forbid set, applied only where it means something.
func sinkTaints(operation string, taints []string) []string {
	if !isScratchSink(operation) {
		return nil
	}
	return taints
}
