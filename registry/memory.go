package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/aurora-capcompute/aurora-dispatchers/builtin"
	"github.com/aurora-capcompute/aurora-dispatchers/memory"
	"github.com/aurora-capcompute/capcompute/sys"
)

// MemorySettings configures one core.memory grant. Subtree chroots the grant
// inside the tenant's space (the grant tree does directory permissions);
// RequireApprovalOnPut gates standing-memory writes behind a human.
type MemorySettings struct {
	Subtree              string `json:"subtree,omitempty"`
	RequireApprovalOnPut bool   `json:"require_approval_on_put,omitempty"`
}

// MemoryRegistration provides tenant-scoped shared memory — the filesystem
// role: cross-session durable state reached as a journaled capability, never
// ambiently (see capcompute docs/ARCHITECTURE.md, "Shared state").
type MemoryRegistration struct{}

func (MemoryRegistration) Matches(syscall string) bool { return syscall == "core.memory" }

func (MemoryRegistration) Normalize(_ string, raw json.RawMessage) (json.RawMessage, error) {
	settings, err := parseMemorySettings(raw)
	if err != nil {
		return nil, err
	}
	return json.Marshal(settings)
}

func (MemoryRegistration) Configure(_ context.Context, raw json.RawMessage, services Services, config *builtin.Config) error {
	settings, err := parseMemorySettings(raw)
	if err != nil {
		return err
	}
	if services.MemoryStore == nil {
		return errors.New("core.memory requires Services.MemoryStore")
	}
	if services.Tenant == "" {
		return errors.New("core.memory requires Services.Tenant")
	}
	config.Handlers = append(config.Handlers, memory.Handler{
		Name:                 memory.Capability,
		Store:                services.MemoryStore,
		Tenant:               services.Tenant,
		Subtree:              settings.Subtree,
		RequireApprovalOnPut: settings.RequireApprovalOnPut,
	})
	scope := "the tenant's shared memory"
	if settings.Subtree != "" {
		scope = fmt.Sprintf("the %q subtree of the tenant's shared memory", settings.Subtree)
	}
	config.Capabilities = append(config.Capabilities,
		sys.Capability{
			Name:        memory.Capability + ".get",
			Description: fmt.Sprintf("Read one key from %s. Keys are relative slash-paths; the response carries the value's current version for compare-and-set writes.", scope),
			InputSchema: json.RawMessage(`{"type":"object","properties":{"key":{"type":"string","minLength":1}},"required":["key"],"additionalProperties":false}`),
		},
		sys.Capability{
			Name:        memory.Capability + ".put",
			Description: fmt.Sprintf("Write one key to %s. Persists across sessions of this tenant. Optional if_version makes the write a compare-and-set: 0 = create only, N = replace exactly version N; a conflict errno means re-read and retry.", scope),
			InputSchema: json.RawMessage(`{"type":"object","properties":{"key":{"type":"string","minLength":1},"value":{},"if_version":{"type":"integer","minimum":0}},"required":["key","value"],"additionalProperties":false}`),
		},
		sys.Capability{
			Name:        memory.Capability + ".list",
			Description: fmt.Sprintf("List keys under a prefix in %s.", scope),
			InputSchema: json.RawMessage(`{"type":"object","properties":{"prefix":{"type":"string"}},"additionalProperties":false}`),
		},
	)
	return nil
}

// parseMemorySettings validates and canonicalizes a core.memory grant's
// settings — the single parse Normalize and Configure share.
func parseMemorySettings(raw json.RawMessage) (MemorySettings, error) {
	var settings MemorySettings
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &settings); err != nil {
			return MemorySettings{}, err
		}
	}
	if strings.HasPrefix(settings.Subtree, "/") || strings.HasSuffix(settings.Subtree, "/") {
		return MemorySettings{}, fmt.Errorf("subtree must be a relative path without leading or trailing slashes")
	}
	if settings.Subtree != "" {
		for _, segment := range strings.Split(settings.Subtree, "/") {
			if segment == "" || segment == "." || segment == ".." {
				return MemorySettings{}, fmt.Errorf("subtree %q contains an invalid path segment", settings.Subtree)
			}
		}
	}
	return settings, nil
}
