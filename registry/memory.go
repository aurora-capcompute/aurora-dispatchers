package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/aurora-capcompute/aurora-dispatchers/builtin"
	"github.com/aurora-capcompute/aurora-dispatchers/memory"
	"github.com/aurora-capcompute/capcompute/sys"
)

// memoryConfig is a core.memory grant's driver configuration: the operations it
// grants (each an ADT case with its data-flow policy) and the subtree it chroots
// into. Subtree scopes every access (the grant tree does directory permissions:
// an agent granted "notes" cannot name anything outside notes/).
type memoryConfig struct {
	Capabilities json.RawMessage `json:"capabilities,omitempty"`
	Subtree      string          `json:"subtree,omitempty"`
}

// memoryOperations are the cases a core.memory grant may enable, each with the
// field schema its args carry (minus the `operation` discriminator, which
// operationBranch injects) and a one-line description.
var memoryOperations = map[string]struct {
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
}

// MemoryRegistration provides tenant-scoped shared memory — the filesystem
// role: cross-session durable state reached as a journaled capability, never
// ambiently (see capcompute docs/ARCHITECTURE.md, "Shared state").
type MemoryRegistration struct{}

func (MemoryRegistration) Matches(syscall string) bool { return syscall == memory.Capability }

func (MemoryRegistration) Normalize(_ string, raw json.RawMessage) (json.RawMessage, error) {
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

func (MemoryRegistration) Configure(_ context.Context, raw json.RawMessage, services Services, out *builtin.Config) error {
	config, grants, err := parseMemoryConfig(raw)
	if err != nil {
		return err
	}
	if services.MemoryStore == nil {
		return errors.New("core.memory requires Services.MemoryStore")
	}
	if services.Tenant == "" {
		return errors.New("core.memory requires Services.Tenant")
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

	out.Handlers = append(out.Handlers, memory.Handler{
		Name:       memory.Capability,
		Store:      services.MemoryStore,
		Tenant:     services.Tenant,
		Subtree:    config.Subtree,
		Operations: operations,
	})
	scope := "the tenant's shared memory"
	if config.Subtree != "" {
		scope = fmt.Sprintf("the %q subtree of the tenant's shared memory", config.Subtree)
	}
	out.Capabilities = append(out.Capabilities, sys.Capability{
		Name: memory.Capability,
		Description: fmt.Sprintf("Tenant memory in %s — keys are relative slash-paths, persisted across this tenant's sessions. Choose an operation:\n- %s.",
			scope, strings.Join(names, "\n- ")),
		InputSchema: OneOfSchema(branches),
	})
	return nil
}

// parseMemoryConfig validates and canonicalizes a core.memory grant's config —
// the single parse Normalize and Configure share. It rejects unknown top-level
// fields, requires at least one granted operation drawn from the known set with
// no duplicates, normalizes each operation's flow policy, and validates subtree.
func parseMemoryConfig(raw json.RawMessage) (memoryConfig, []OperationGrant, error) {
	var config memoryConfig
	if len(raw) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&config); err != nil {
			return memoryConfig{}, nil, err
		}
	}
	grants, err := DecodeOperationGrants(config.Capabilities)
	if err != nil {
		return memoryConfig{}, nil, err
	}
	if len(grants) == 0 {
		return memoryConfig{}, nil, fmt.Errorf("capabilities must grant at least one operation (get, put, list)")
	}
	seen := make(map[string]struct{}, len(grants))
	for i := range grants {
		operation := strings.TrimSpace(grants[i].Operation)
		if _, ok := memoryOperations[operation]; !ok {
			return memoryConfig{}, nil, fmt.Errorf("unknown memory operation %q (want get, put, or list)", grants[i].Operation)
		}
		if _, dup := seen[operation]; dup {
			return memoryConfig{}, nil, fmt.Errorf("duplicate memory operation %q", operation)
		}
		seen[operation] = struct{}{}
		grants[i].Operation = operation
		if grants[i].FlowPolicy, err = grants[i].FlowPolicy.Normalized(); err != nil {
			return memoryConfig{}, nil, fmt.Errorf("operation %q: %w", operation, err)
		}
	}
	sortOperationGrants(grants)
	if err := validateSubtree(config.Subtree); err != nil {
		return memoryConfig{}, nil, err
	}
	return config, grants, nil
}

// validateSubtree enforces chroot semantics: a relative path with no leading or
// trailing slash and no empty/./.. segment.
func validateSubtree(subtree string) error {
	if strings.HasPrefix(subtree, "/") || strings.HasSuffix(subtree, "/") {
		return fmt.Errorf("subtree must be a relative path without leading or trailing slashes")
	}
	if subtree != "" {
		for _, segment := range strings.Split(subtree, "/") {
			if segment == "" || segment == "." || segment == ".." {
				return fmt.Errorf("subtree %q contains an invalid path segment", subtree)
			}
		}
	}
	return nil
}

func sortOperationGrants(grants []OperationGrant) {
	sort.Slice(grants, func(i, j int) bool { return grants[i].Operation < grants[j].Operation })
}
