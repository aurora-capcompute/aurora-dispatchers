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

// Memory scopes. A core.memory mount addresses exactly one scope, and every
// physical key is prefixed by the tenant (host-set), so no scope can ever cross a
// tenant boundary. There is deliberately no tenant-wide scope — the most-shared a
// key can be is a named shared space.
const (
	// scopeProcess is private to the calling process.
	scopeProcess = "process"
	// scopeSession is shared across the calling session's processes — its whole
	// spawn tree — and isolated from every other session.
	scopeSession = "session"
	// sharedScopePrefix marks a named tenant-local shared space: "shared:<name>".
	// Any grant in the tenant that names the same space shares it (publish/read),
	// so cross-session sharing is explicit and visible in both manifests.
	sharedScopePrefix = "shared:"
)

// sharedNamePattern constrains a shared space name to a safe path-free identifier.
var sharedNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// memoryMount is one entry of a core.memory grant's capabilities: the scope it
// mounts, an optional subtree chroot within that scope, the operations allowed on
// it, and the data-flow policy. Scope is a whole-mount property; a call names the
// scope it addresses and the handler enforces it.
type memoryMount struct {
	Scope           string   `json:"scope"`
	Subtree         string   `json:"subtree,omitempty"`
	Operations      []string `json:"operations"`
	RequireApproval *bool    `json:"require_approval,omitempty"`
	FlowPolicy
}

// memoryConfig is a core.memory grant's driver configuration: a set of mounts.
type memoryConfig struct {
	Capabilities []memoryMount `json:"capabilities,omitempty"`
}

// memoryOperations are the cases a core.memory grant may enable, each with the
// field schema its args carry (minus the `operation` and `scope` fields the
// registry injects) and a one-line description.
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

func (MemoryRegistration) Configure(_ context.Context, raw json.RawMessage, services Services, out *builtin.Config) error {
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
	out.Handlers = append(out.Handlers, memory.Handler{
		Name:   memory.Capability,
		Store:  services.MemoryStore,
		Tenant: services.Tenant,
		Mounts: mounts,
	})
	out.Capabilities = append(out.Capabilities, sys.Capability{
		Name:        memory.Capability,
		Description: memoryDescription(config),
		InputSchema: memorySchema(config),
	})
	return nil
}

// buildMemoryMounts resolves each mount's scope to its physical key prefix inside
// the tenant, using the calling process's identity for the self-scopes.
func buildMemoryMounts(config memoryConfig, services Services) (map[string]memory.Mount, error) {
	mounts := make(map[string]memory.Mount, len(config.Capabilities))
	for _, m := range config.Capabilities {
		prefix, err := scopePrefix(m.Scope, services)
		if err != nil {
			return nil, err
		}
		if m.Subtree != "" {
			prefix += "/" + m.Subtree
		}
		ops := make(map[string]struct{}, len(m.Operations))
		for _, op := range m.Operations {
			ops[op] = struct{}{}
		}
		mounts[m.Scope] = memory.Mount{
			Prefix:          prefix,
			Operations:      ops,
			RequireApproval: m.RequireApproval != nil && *m.RequireApproval,
			Labels:          m.Labels,
			Taints:          m.Taints,
		}
	}
	return mounts, nil
}

// scopePrefix maps a scope to its physical key prefix within the tenant. The
// self-scopes need the process credential; a missing id fails the build closed.
func scopePrefix(scope string, services Services) (string, error) {
	switch {
	case scope == scopeProcess:
		if services.ProcessID == "" {
			return "", errors.New("core.memory: the process scope needs the calling process's identity")
		}
		return "p/" + services.ProcessID, nil
	case scope == scopeSession:
		if services.SessionID == "" {
			return "", errors.New("core.memory: the session scope needs the calling session's identity")
		}
		return "s/" + services.SessionID, nil
	case strings.HasPrefix(scope, sharedScopePrefix):
		return "shared/" + scope[len(sharedScopePrefix):], nil
	default:
		return "", fmt.Errorf("unknown memory scope %q", scope)
	}
}

// parseMemoryConfig validates and canonicalizes a core.memory grant — the single
// parse Normalize and Configure share. It rejects unknown fields, requires at
// least one mount, each with a valid scope (no duplicate scope), a valid subtree,
// at least one known operation, and a normalized flow policy.
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
	seenScope := make(map[string]struct{}, len(config.Capabilities))
	for i := range config.Capabilities {
		m := &config.Capabilities[i]
		if err := validateScope(m.Scope); err != nil {
			return memoryConfig{}, fmt.Errorf("mount %d: %w", i, err)
		}
		if _, dup := seenScope[m.Scope]; dup {
			return memoryConfig{}, fmt.Errorf("scope %q is mounted more than once", m.Scope)
		}
		seenScope[m.Scope] = struct{}{}
		if err := validateSubtree(m.Subtree); err != nil {
			return memoryConfig{}, fmt.Errorf("mount %q: %w", m.Scope, err)
		}
		ops, err := normalizeMemoryOperations(m.Operations)
		if err != nil {
			return memoryConfig{}, fmt.Errorf("mount %q: %w", m.Scope, err)
		}
		m.Operations = ops
		if m.FlowPolicy, err = m.FlowPolicy.Normalized(); err != nil {
			return memoryConfig{}, fmt.Errorf("mount %q: %w", m.Scope, err)
		}
	}
	sort.Slice(config.Capabilities, func(i, j int) bool { return config.Capabilities[i].Scope < config.Capabilities[j].Scope })
	return config, nil
}

// validateScope accepts process, session, or shared:<name>. There is no
// tenant-wide scope — that permissiveness is removed by construction.
func validateScope(scope string) error {
	switch {
	case scope == scopeProcess || scope == scopeSession:
		return nil
	case strings.HasPrefix(scope, sharedScopePrefix):
		if name := scope[len(sharedScopePrefix):]; !sharedNamePattern.MatchString(name) {
			return fmt.Errorf("invalid shared space name in scope %q (want shared:<name>, name of letters/digits/._-)", scope)
		}
		return nil
	case scope == "":
		return errors.New("scope is required (process, session, or shared:<name>)")
	default:
		return fmt.Errorf("unknown scope %q (want process, session, or shared:<name>) — there is no tenant-wide scope", scope)
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
// operations, each carrying a `scope` enum of the scopes that grant it. When more
// than one scope is mounted, `scope` is required on every call so the target is
// never ambiguous; a single-mount grant may omit it.
func memorySchema(config memoryConfig) json.RawMessage {
	scopesByOp := map[string][]string{}
	for _, m := range config.Capabilities {
		for _, op := range m.Operations {
			scopesByOp[op] = append(scopesByOp[op], m.Scope)
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
		scopes := scopesByOp[op]
		sort.Strings(scopes)
		branch, _ := OperationBranch(op, withScopeProperty(memoryOperations[op].schema, scopes, scopeRequired))
		branches = append(branches, branch)
	}
	return OneOfSchema(branches)
}

// withScopeProperty adds the `scope` enum to an operation's object schema,
// marking it required when the grant has multiple scopes.
func withScopeProperty(base json.RawMessage, scopes []string, required bool) json.RawMessage {
	var schema map[string]json.RawMessage
	_ = json.Unmarshal(base, &schema)
	props := map[string]json.RawMessage{}
	if raw, ok := schema["properties"]; ok {
		_ = json.Unmarshal(raw, &props)
	}
	props["scope"], _ = json.Marshal(map[string]any{"type": "string", "enum": scopes})
	schema["properties"], _ = json.Marshal(props)
	if required {
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
	b.WriteString("Tenant memory — durable key/value persisted across this tenant's sessions; keys are relative slash-paths. Each call names a `scope` (below) and a `key`. Scopes: process (this process only), session (this conversation), shared:<name> (a named cross-session space). Granted:")
	for _, m := range config.Capabilities {
		fmt.Fprintf(&b, "\n- %s: %s", m.Scope, strings.Join(m.Operations, "/"))
		if m.Subtree != "" {
			fmt.Fprintf(&b, " (under %q)", m.Subtree)
		}
	}
	return b.String()
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
