package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/aurora-capcompute/aurora-dispatchers/builtin"
	"github.com/aurora-capcompute/aurora-dispatchers/memory"
	"github.com/aurora-capcompute/capcompute/sys"
)

// sharedNamePattern constrains a shared space name to a safe path-free
// identifier — the name becomes a physical key segment, so it may not carry
// slashes or dot segments.
var sharedNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// memoryMount is one entry of a core.memory grant's capabilities: the scope it
// mounts, the operations allowed on it, and the data-flow policy. Scope is a
// tagged union kept as two fields — `scope` is the tag (process, session,
// shared) and `space` is the shared variant's payload, required exactly when the
// scope is shared. Every physical key is prefixed by the host-set tenant, so no
// mount can ever cross a tenant boundary, and there is deliberately no
// tenant-wide scope — the most-shared a key can be is a named shared space.
type memoryMount struct {
	Scope           string   `json:"scope"`
	Space           string   `json:"space,omitempty"`
	Operations      []string `json:"operations"`
	RequireApproval *bool    `json:"require_approval,omitempty"`
	FlowPolicy
}

// memoryConfig is a core.memory grant's driver configuration: a set of mounts.
type memoryConfig struct {
	Capabilities []memoryMount `json:"capabilities,omitempty"`
}

// memoryOperations are the cases a core.memory grant may enable, each with the
// field schema its args carry (minus the `operation` discriminator and the
// scope/space selector the registry injects) and a one-line description.
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
	"search": {
		schema:      json.RawMessage(`{"type":"object","properties":{"key":{"type":"string","minLength":1},"pattern":{"type":"string","minLength":1},"ignore_case":{"type":"boolean"},"context":{"type":"integer","minimum":0,"maximum":5},"max_matches":{"type":"integer","minimum":1,"maximum":100}},"required":["key","pattern"],"additionalProperties":false}`),
		description: "search: grep a stored value with an RE2 regex — returns matching lines with line numbers (and optional surrounding context), bounded, so a large value is queried without reading it whole",
	},
}

// MemoryRegistration provides tenant-scoped shared memory partitioned by scope —
// the filesystem role: cross-session durable state reached as a journaled
// capability, never ambiently (see capcompute docs/ARCHITECTURE.md).
type MemoryRegistration struct{}

func (MemoryRegistration) Matches(syscall string) bool { return syscall == memory.Capability }

func (MemoryRegistration) Normalize(_ string, raw json.RawMessage) (json.RawMessage, error) {
	config, err := parseMemoryConfig(raw)
	if err != nil {
		return nil, err
	}
	return json.Marshal(config)
}

func (MemoryRegistration) Configure(_ context.Context, raw json.RawMessage, services Services, out *builtin.Table) error {
	config, err := parseMemoryConfig(raw)
	if err != nil {
		return err
	}
	if services.MemoryStore == nil {
		return errors.New("core.memory requires Services.MemoryStore")
	}
	if services.Tenant == "" {
		return errors.New("core.memory requires Services.Tenant")
	}
	mounts, err := buildMemoryMounts(config, services)
	if err != nil {
		return err
	}
	handler := memory.Handler{
		Name:   memory.Capability,
		Store:  services.MemoryStore,
		Tenant: services.Tenant,
		Mounts: mounts,
	}
	ops, branches := memoryBranches(config)
	entries := make([]builtin.Entry, 0, len(ops))
	for i, op := range ops {
		entries = append(entries, builtin.Entry{
			Key:         builtin.Key{Syscall: memory.Capability, Operation: op},
			Description: memoryOperations[op].description,
			Input:       branches[i],
			Handler:     handler,
		})
	}
	return out.Add(memory.Capability, builtin.Field("operation"), entries, sys.Capability{
		Name:        memory.Capability,
		Description: memoryDescription(config),
		InputSchema: OneOfSchema(branches),
	})
}

// buildMemoryMounts resolves each mount's scope to its physical key prefix inside
// the tenant, using the calling process's identity for the self-scopes.
func buildMemoryMounts(config memoryConfig, services Services) ([]memory.Mount, error) {
	mounts := make([]memory.Mount, 0, len(config.Capabilities))
	for _, m := range config.Capabilities {
		prefix, err := scopePrefix(m.Scope, m.Space, services)
		if err != nil {
			return nil, err
		}
		ops := make(map[string]struct{}, len(m.Operations))
		for _, op := range m.Operations {
			ops[op] = struct{}{}
		}
		mounts = append(mounts, memory.Mount{
			Scope:           m.Scope,
			Space:           m.Space,
			Prefix:          prefix,
			Operations:      ops,
			RequireApproval: m.RequireApproval != nil && *m.RequireApproval,
			Labels:          m.Labels,
			Taints:          m.Taints,
		})
	}
	return mounts, nil
}

// scopePrefix maps a scope to its physical key prefix within the tenant. The
// self-scopes need the process credential; a missing id fails the build closed.
func scopePrefix(scope, space string, services Services) (string, error) {
	switch scope {
	case memory.ScopeProcess:
		if services.ProcessID == "" {
			return "", errors.New("core.memory: the process scope needs the calling process's identity")
		}
		return "p/" + services.ProcessID, nil
	case memory.ScopeSession:
		if services.SessionID == "" {
			return "", errors.New("core.memory: the session scope needs the calling session's identity")
		}
		return "s/" + services.SessionID, nil
	case memory.ScopeShared:
		return "shared/" + space, nil
	default:
		return "", fmt.Errorf("unknown memory scope %q", scope)
	}
}

// parseMemoryConfig validates and canonicalizes a core.memory grant — the single
// parse Normalize and Configure share. It rejects unknown fields, requires at
// least one mount, each with a valid scope/space pair (no duplicate mount), at
// least one known operation, and a normalized flow policy.
func parseMemoryConfig(raw json.RawMessage) (memoryConfig, error) {
	var config memoryConfig
	if len(raw) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&config); err != nil {
			return memoryConfig{}, err
		}
	}
	if len(config.Capabilities) == 0 {
		return memoryConfig{}, errors.New("capabilities must grant at least one mount")
	}
	seen := make(map[string]struct{}, len(config.Capabilities))
	for i := range config.Capabilities {
		m := &config.Capabilities[i]
		if err := validateScope(m.Scope, m.Space); err != nil {
			return memoryConfig{}, fmt.Errorf("mount %d: %w", i, err)
		}
		key := m.Scope + "\x00" + m.Space
		if _, dup := seen[key]; dup {
			return memoryConfig{}, fmt.Errorf("mount %s is granted more than once", describeMount(*m))
		}
		seen[key] = struct{}{}
		ops, err := normalizeMemoryOperations(m.Operations)
		if err != nil {
			return memoryConfig{}, fmt.Errorf("mount %s: %w", describeMount(*m), err)
		}
		m.Operations = ops
		if m.FlowPolicy, err = m.FlowPolicy.Normalized(); err != nil {
			return memoryConfig{}, fmt.Errorf("mount %s: %w", describeMount(*m), err)
		}
	}
	sort.Slice(config.Capabilities, func(i, j int) bool {
		a, b := config.Capabilities[i], config.Capabilities[j]
		if a.Scope != b.Scope {
			return a.Scope < b.Scope
		}
		return a.Space < b.Space
	})
	return config, nil
}

// validateScope accepts process, session, or shared — with `space` naming the
// shared space exactly when the scope is shared. There is no tenant-wide scope —
// that permissiveness is removed by construction.
func validateScope(scope, space string) error {
	switch scope {
	case memory.ScopeProcess, memory.ScopeSession:
		if space != "" {
			return fmt.Errorf("space applies only to the shared scope, not %q", scope)
		}
		return nil
	case memory.ScopeShared:
		if space == "" {
			return errors.New("the shared scope requires a space (the shared space's name)")
		}
		if !sharedNamePattern.MatchString(space) {
			return fmt.Errorf("invalid shared space name %q (letters/digits/._- only)", space)
		}
		return nil
	case "":
		return errors.New("scope is required (process, session, or shared)")
	default:
		return fmt.Errorf("unknown scope %q (want process, session, or shared) — there is no tenant-wide scope", scope)
	}
}

// normalizeMemoryOperations validates a mount's operation set against the known
// cases, de-duplicates, and sorts.
func normalizeMemoryOperations(ops []string) ([]string, error) {
	if len(ops) == 0 {
		return nil, errors.New("operations must list at least one of get, put, list, search")
	}
	seen := make(map[string]struct{}, len(ops))
	out := make([]string, 0, len(ops))
	for _, op := range ops {
		op = strings.TrimSpace(op)
		if _, ok := memoryOperations[op]; !ok {
			return nil, fmt.Errorf("unknown operation %q (want get, put, list, search)", op)
		}
		if _, dup := seen[op]; dup {
			continue
		}
		seen[op] = struct{}{}
		out = append(out, op)
	}
	sort.Strings(out)
	return out, nil
}

// memorySchema publishes the guest-facing input schema: a oneOf over the granted
// operations, each carrying a `scope` enum of the scopes that grant it and — when
// any of those are shared — a `space` enum of the granting shared spaces. With
// more than one mount, `scope` is required on every call so the target is never
// ambiguous; a single-mount grant may omit the selector. Space's
// required-exactly-when-shared rule is conditional, so the handler enforces it.
func memorySchema(config memoryConfig) json.RawMessage {
	_, branches := memoryBranches(config)
	return OneOfSchema(branches)
}

// memoryBranches is the per-operation half of the schema: one branch per granted
// operation, in order, alongside the operation names the index keys on.
func memoryBranches(config memoryConfig) ([]string, []json.RawMessage) {
	scopesByOp := map[string]map[string]struct{}{}
	spacesByOp := map[string][]string{}
	for _, m := range config.Capabilities {
		for _, op := range m.Operations {
			if scopesByOp[op] == nil {
				scopesByOp[op] = map[string]struct{}{}
			}
			scopesByOp[op][m.Scope] = struct{}{}
			if m.Scope == memory.ScopeShared {
				spacesByOp[op] = append(spacesByOp[op], m.Space)
			}
		}
	}
	scopeRequired := len(config.Capabilities) > 1
	ops := make([]string, 0, len(scopesByOp))
	for op := range scopesByOp {
		ops = append(ops, op)
	}
	sort.Strings(ops)
	branches := make([]json.RawMessage, 0, len(ops))
	for _, op := range ops {
		scopes := make([]string, 0, len(scopesByOp[op]))
		for scope := range scopesByOp[op] {
			scopes = append(scopes, scope)
		}
		sort.Strings(scopes)
		spaces := spacesByOp[op]
		sort.Strings(spaces)
		branch, _ := OperationBranch(op, withMountSelector(memoryOperations[op].schema, scopes, spaces, scopeRequired))
		branches = append(branches, branch)
	}
	return ops, branches
}

// withMountSelector adds the mount-selector properties to an operation's object
// schema: the `scope` enum (required when the grant has multiple mounts) and,
// when shared spaces grant the operation, the `space` enum naming them.
func withMountSelector(base json.RawMessage, scopes, spaces []string, scopeRequired bool) json.RawMessage {
	var schema map[string]json.RawMessage
	_ = json.Unmarshal(base, &schema)
	props := map[string]json.RawMessage{}
	if raw, ok := schema["properties"]; ok {
		_ = json.Unmarshal(raw, &props)
	}
	props["scope"], _ = json.Marshal(map[string]any{"type": "string", "enum": scopes})
	if len(spaces) > 0 {
		props["space"], _ = json.Marshal(map[string]any{"type": "string", "enum": spaces})
	}
	schema["properties"], _ = json.Marshal(props)
	if scopeRequired {
		var req []string
		if raw, ok := schema["required"]; ok {
			_ = json.Unmarshal(raw, &req)
		}
		schema["required"], _ = json.Marshal(append(req, "scope"))
	}
	out, _ := json.Marshal(schema)
	return out
}

func memoryDescription(config memoryConfig) string {
	var b strings.Builder
	b.WriteString("Tenant memory — durable key/value persisted across this tenant's sessions; keys are relative slash-paths. Each call names a `scope` and a `key`; a shared mount is addressed with scope \"shared\" plus its `space` name. Scopes: process (this process only), session (this conversation), shared (a named cross-session space). Granted:")
	for _, m := range config.Capabilities {
		fmt.Fprintf(&b, "\n- %s: %s", describeMount(m), strings.Join(m.Operations, "/"))
	}
	return b.String()
}

// describeMount names a mount for descriptions and errors: `process`, `session`,
// or `shared "team-kb"`.
func describeMount(m memoryMount) string {
	if m.Scope == memory.ScopeShared {
		return fmt.Sprintf("shared %q", m.Space)
	}
	return m.Scope
}
