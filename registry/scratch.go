package registry

import (
	"context"
	"encoding/json"
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

// ScratchRegistration provides core.scratch: a process-local, ephemeral KV with
// the same get/put/list/search operations (and ADT shape) as core.memory, but
// backed by a fresh in-memory store built per process and discarded when the
// process ends. It is the right home for large transient content — a fetched
// page offloaded out of the model's context: private to the process, never
// written to the durable tenant store, and gone when the run is over. The store
// lives for one activation; a process that parks and reactivates starts with an
// empty scratch (the journaled summary/excerpt of any offload survive
// regardless — only a full-text re-query would miss and prompt a re-fetch).
type ScratchRegistration struct{}

func (ScratchRegistration) Matches(syscall string) bool { return syscall == ScratchCapability }

func (ScratchRegistration) Normalize(_ string, raw json.RawMessage) (json.RawMessage, error) {
	config, grants, err := parseMemoryConfig(raw)
	if err != nil {
		return nil, err
	}
	// parseMemoryConfig already returns grants in canonical (sorted) order.
	if config.Capabilities, err = json.Marshal(grants); err != nil {
		return nil, err
	}
	return json.Marshal(config)
}

func (ScratchRegistration) Configure(_ context.Context, raw json.RawMessage, _ Services, out *builtin.Config) error {
	config, grants, err := parseMemoryConfig(raw)
	if err != nil {
		return err
	}

	operations := make(map[string]memory.Operation, len(grants))
	branches := make([]json.RawMessage, 0, len(grants))
	names := make([]string, 0, len(grants))
	for _, grant := range grants {
		operations[grant.Operation] = memory.Operation{
			RequireApproval: grant.RequireApproval != nil && *grant.RequireApproval,
			Labels:          grant.Labels,
			Taints:          grant.Taints,
		}
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
	out.Handlers = append(out.Handlers, memory.Handler{
		Name:       ScratchCapability,
		Store:      memory.NewMapStore(),
		Tenant:     scratchTenant,
		Subtree:    config.Subtree,
		Operations: operations,
	})
	out.Capabilities = append(out.Capabilities, sys.Capability{
		Name: ScratchCapability,
		Description: fmt.Sprintf("Process-local scratch memory — ephemeral and private to this process, cleared when it ends, never written to shared storage. Keys are relative slash-paths. Stash large content here and query it with search rather than carrying it in the conversation. Choose an operation:\n- %s.",
			strings.Join(names, "\n- ")),
		InputSchema: OneOfSchema(branches),
	})
	return nil
}
