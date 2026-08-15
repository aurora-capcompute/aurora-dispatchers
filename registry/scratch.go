package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/aurora-capcompute/aurora-dispatchers/builtin"
	"github.com/aurora-capcompute/aurora-dispatchers/memory"
	"github.com/aurora-capcompute/capcompute/sys"
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

func (ScratchRegistration) Normalize(_ string, raw json.RawMessage) (json.RawMessage, error) {
	config, grants, err := parseScratchConfig(raw)
	if err != nil {
		return nil, err
	}
	// parseScratchConfig already returns grants in canonical (sorted) order.
	if config.Capabilities, err = json.Marshal(grants); err != nil {
		return nil, err
	}
	return json.Marshal(config)
}

func (ScratchRegistration) Configure(_ context.Context, raw json.RawMessage, _ Services, out *builtin.Table) error {
	_, grants, err := parseScratchConfig(raw)
	if err != nil {
		return err
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
		branch, err := OperationBranch(grant.Operation, memoryOperations[grant.Operation].schema)
		if err != nil {
			return err
		}
		branches = append(branches, branch)
		names = append(names, memoryOperations[grant.Operation].description)
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
		Mounts: []memory.Mount{{
			Operations:      ops,
			RequireApproval: requireApproval,
			Labels:          labels,
			Taints:          taints,
		}},
	}
	entries := make([]builtin.Entry, 0, len(grants))
	for i, grant := range grants {
		entries = append(entries, builtin.Entry{
			Key:         builtin.Key{Syscall: ScratchCapability, Operation: grant.Operation},
			Description: memoryOperations[grant.Operation].description,
			Input:       branches[i],
			Handler:     handler,
		})
	}
	return out.Add(ScratchCapability, "operation", builtin.Field("operation"), entries, sys.Capability{
		Name: ScratchCapability,
		Description: fmt.Sprintf("Process-local scratch memory — ephemeral and private to this process, cleared when it ends, never written to shared storage. Keys are relative slash-paths. Stash large content here and query it with search rather than carrying it in the conversation. Choose an operation:\n- %s.",
			strings.Join(names, "\n- ")),
		InputSchema: OneOfSchema(branches),
	})
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
		if _, ok := memoryOperations[operation]; !ok {
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
