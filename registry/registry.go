package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aurora-capcompute/aurora-dispatchers/builtin"
	"github.com/aurora-capcompute/aurora-dispatchers/internet"
	"github.com/aurora-capcompute/aurora-dispatchers/mcp"
	"github.com/aurora-capcompute/aurora-dispatchers/memory"
	"github.com/aurora-capcompute/aurora-dispatchers/timer"
	"github.com/aurora-capcompute/capcompute/sys"
	"strings"
	"time"
)

type Services struct {
	MCPServers map[string]mcp.ServerConfig
	// Tenant identifies whose memory space core.memory grants open. It is a
	// host-side fact about the agent instance, never guest-supplied.
	Tenant string
	// MemoryStore is the durable KV store behind core.memory grants.
	MemoryStore memory.Store
}

// Registration builds a leaf I/O driver for one syscall. A registration is
// selected by the granted syscall; the capability names it publishes are
// canonical to the driver (timer.set, memory.get/put/list, internet.read,
// openai.*, mcp.<server>.<tool>) — the manifest names nothing.
type Registration interface {
	Matches(syscall string) bool
	Normalize(syscall string, settings json.RawMessage) (json.RawMessage, error)
	Configure(ctx context.Context, settings json.RawMessage, services Services, config *builtin.Config) error
}

type Registry struct {
	registrations []Registration
}

func New(registrations ...Registration) *Registry {
	return &Registry{registrations: append([]Registration(nil), registrations...)}
}

// Try-Confirm/Cancel is deliberately not a driver. A reservation is a real
// write to the participant that owns the resource — the third-party system
// every reader treats as the source of truth — so it is an ordinary dispatch:
// reserve, register the release with sys.compensate (the runtime guarantees it
// runs if the section aborts or fails), confirm as the last call before
// sys.commit. Pending state, and any expiry policy, belong to the resource
// owner (Pardon & Pautasso's RESTful TCC puts them on the participant); an
// orchestrator-side hold table would be a reservation no other booker can see.
func Default() *Registry {
	return New(InternetRegistration{}, MCPRegistration{}, TimerRegistration{}, MemoryRegistration{})
}

func (r *Registry) Normalize(syscall string, settings json.RawMessage) (json.RawMessage, error) {
	for _, registration := range r.registrations {
		if registration.Matches(syscall) {
			return registration.Normalize(syscall, settings)
		}
	}
	return nil, fmt.Errorf("unsupported syscall %q", syscall)
}

// Entry is one leaf grant to build: `Syscall` selects the registration.
// `Hidden` keeps the grant dispatchable but off the program's discoverable
// menu.
type Entry struct {
	Syscall  string
	Settings json.RawMessage
	Hidden   bool
}

func (r *Registry) Build(ctx context.Context, entries []Entry, services Services) (builtin.Config, error) {
	var config builtin.Config
	for _, entry := range entries {
		var selected Registration
		for _, registration := range r.registrations {
			if registration.Matches(entry.Syscall) {
				selected = registration
				break
			}
		}
		if selected == nil {
			return builtin.Config{}, fmt.Errorf("unsupported syscall %q", entry.Syscall)
		}
		before := len(config.Capabilities)
		if err := selected.Configure(ctx, entry.Settings, services, &config); err != nil {
			return builtin.Config{}, err
		}
		// A hidden grant hides every capability it publishes (e.g. the LLM
		// publishes openai.* operations under a hidden entry).
		if entry.Hidden {
			for i := before; i < len(config.Capabilities); i++ {
				config.Capabilities[i].Hidden = true
			}
		}
	}
	return config, nil
}

// InternetPermission is one allowlisted request the grant may make.
type InternetPermission struct {
	RequestType string `json:"requestType"`
	Domain      string `json:"domain"`
}

type InternetSettings struct {
	Permissions      []InternetPermission `json:"permissions"`
	TimeoutMS        int64                `json:"timeout_ms,omitempty"`
	MaxResponseBytes int64                `json:"max_response_bytes,omitempty"`
	RequireApproval  bool                 `json:"require_approval,omitempty"`
}

type InternetRegistration struct{}

func (InternetRegistration) Matches(syscallType string) bool { return syscallType == "core.internet" }

func (InternetRegistration) Normalize(_ string, raw json.RawMessage) (json.RawMessage, error) {
	settings := InternetSettings{
		TimeoutMS:        int64(internet.DefaultTimeout / time.Millisecond),
		MaxResponseBytes: internet.DefaultMaxResponseBytes,
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &settings); err != nil {
			return nil, err
		}
	}
	if len(settings.Permissions) == 0 {
		return nil, fmt.Errorf("permissions must contain at least one {requestType, domain}")
	}
	for i, p := range settings.Permissions {
		method := strings.ToUpper(strings.TrimSpace(p.RequestType))
		if method == "" {
			method = "GET"
		}
		if method != "GET" {
			return nil, fmt.Errorf("permission %d: only GET is supported, got %q", i, p.RequestType)
		}
		domain := strings.TrimSpace(p.Domain)
		if domain == "" {
			return nil, fmt.Errorf("permission %d: domain is empty", i)
		}
		settings.Permissions[i] = InternetPermission{RequestType: method, Domain: domain}
	}
	if settings.TimeoutMS <= 0 {
		return nil, fmt.Errorf("timeout_ms must be positive")
	}
	if settings.MaxResponseBytes <= 0 {
		return nil, fmt.Errorf("max_response_bytes must be positive")
	}
	return json.Marshal(settings)
}

func (InternetRegistration) Configure(
	_ context.Context,
	raw json.RawMessage,
	_ Services,
	config *builtin.Config,
) error {
	normalized, err := (InternetRegistration{}).Normalize("core.internet", raw)
	if err != nil {
		return err
	}
	var settings InternetSettings
	if err := json.Unmarshal(normalized, &settings); err != nil {
		return err
	}
	entries := make([]string, 0, len(settings.Permissions))
	domains := make([]string, 0, len(settings.Permissions))
	for _, p := range settings.Permissions {
		// A bare domain allows https for that host; an explicit scheme is honored.
		origin := p.Domain
		if !strings.Contains(origin, "://") {
			origin = "https://" + origin
		}
		entries = append(entries, p.RequestType+":"+origin)
		domains = append(domains, p.Domain)
	}
	policy, err := internet.ParseAllowlist(strings.Join(entries, ","))
	if err != nil {
		return err
	}
	client := internet.NewConfiguredClient(
		policy,
		time.Duration(settings.TimeoutMS)*time.Millisecond,
		settings.MaxResponseBytes,
	)
	config.Handlers = append(config.Handlers, builtin.InternetHandler{
		Name:            internet.Capability,
		Reader:          client,
		RequireApproval: settings.RequireApproval,
	})
	config.Capabilities = append(config.Capabilities, sys.Capability{
		Name:        internet.Capability,
		Description: "Read textual content with HTTP GET. Allowed domains: " + strings.Join(domains, ", "),
		InputSchema: json.RawMessage(`{"type":"object","properties":{"method":{"type":"string","const":"GET"},"url":{"type":"string","format":"uri"}},"required":["method","url"],"additionalProperties":false}`),
	})
	return nil
}

type MCPSettings struct {
	ServerID string   `json:"server_id,omitempty"`
	Tools    []string `json:"tools,omitempty"`
}

type MCPRegistration struct{}

func (MCPRegistration) Matches(syscallType string) bool { return syscallType == "core.mcp" }

func (MCPRegistration) Normalize(_ string, raw json.RawMessage) (json.RawMessage, error) {
	var settings MCPSettings
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &settings); err != nil {
			return nil, err
		}
	}
	settings.ServerID = strings.TrimSpace(settings.ServerID)
	if settings.ServerID == "" {
		return nil, errors.New("server_id is required")
	}
	return json.Marshal(settings)
}

func (MCPRegistration) Configure(
	ctx context.Context,
	raw json.RawMessage,
	services Services,
	config *builtin.Config,
) error {
	normalized, err := (MCPRegistration{}).Normalize("core.mcp", raw)
	if err != nil {
		return err
	}
	var settings MCPSettings
	if err := json.Unmarshal(normalized, &settings); err != nil {
		return err
	}
	server, ok := services.MCPServers[settings.ServerID]
	if !ok {
		return fmt.Errorf("MCP server %q is not registered", settings.ServerID)
	}
	handler, err := mcp.NewHandler(ctx, server, settings.Tools)
	if err != nil {
		return fmt.Errorf("initialize MCP server %q: %w", settings.ServerID, err)
	}
	config.MCP = append(config.MCP, handler)
	config.Capabilities = append(config.Capabilities, handler.Capabilities()...)
	return nil
}

type TimerSettings struct {
	MaxDurationMS int64 `json:"max_duration_ms,omitempty"`
}

type TimerRegistration struct{}

func (TimerRegistration) Matches(syscallType string) bool { return syscallType == "core.timer" }

func (TimerRegistration) Normalize(_ string, raw json.RawMessage) (json.RawMessage, error) {
	settings := TimerSettings{
		MaxDurationMS: int64(timer.DefaultMaxDuration / time.Millisecond),
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &settings); err != nil {
			return nil, err
		}
	}
	if settings.MaxDurationMS <= 0 {
		return nil, fmt.Errorf("max_duration_ms must be positive")
	}
	return json.Marshal(settings)
}

func (TimerRegistration) Configure(
	_ context.Context,
	raw json.RawMessage,
	_ Services,
	config *builtin.Config,
) error {
	normalized, err := (TimerRegistration{}).Normalize("core.timer", raw)
	if err != nil {
		return err
	}
	var settings TimerSettings
	if err := json.Unmarshal(normalized, &settings); err != nil {
		return err
	}
	maxDuration := time.Duration(settings.MaxDurationMS) * time.Millisecond
	config.Handlers = append(config.Handlers, timer.Handler{Name: timer.Capability, MaxDuration: maxDuration})
	config.Capabilities = append(config.Capabilities, sys.Capability{
		Name: timer.Capability,
		Description: fmt.Sprintf(
			"Set a relative timer and be replayed when it fires. The process pauses until the duration elapses, then continues. Maximum %s.",
			maxDuration,
		),
		InputSchema: json.RawMessage(`{"type":"object","properties":{"duration_seconds":{"type":"integer","minimum":1},"label":{"type":"string"}},"required":["duration_seconds"],"additionalProperties":false}`),
	})
	return nil
}

// MemorySettings configures one core.memory grant. Subtree chroots the grant
// inside the tenant's space (the grant tree does directory permissions);
// require_approval_on_put gates standing-memory writes behind a human.
type MemorySettings struct {
	Subtree              string `json:"subtree,omitempty"`
	RequireApprovalOnPut bool   `json:"require_approval_on_put,omitempty"`
}

// MemoryRegistration provides tenant-scoped shared memory — the filesystem
// role: cross-session durable state reached as a journaled capability, never
// ambiently (see capcompute docs/ARCHITECTURE.md, "Shared state").
type MemoryRegistration struct{}

func (MemoryRegistration) Matches(syscallType string) bool { return syscallType == "core.memory" }

func (MemoryRegistration) Normalize(_ string, raw json.RawMessage) (json.RawMessage, error) {
	var settings MemorySettings
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &settings); err != nil {
			return nil, err
		}
	}
	if strings.HasPrefix(settings.Subtree, "/") || strings.HasSuffix(settings.Subtree, "/") {
		return nil, fmt.Errorf("subtree must be a relative path without leading or trailing slashes")
	}
	for _, segment := range strings.Split(settings.Subtree, "/") {
		if settings.Subtree != "" && (segment == "" || segment == "." || segment == "..") {
			return nil, fmt.Errorf("subtree %q contains an invalid path segment", settings.Subtree)
		}
	}
	return json.Marshal(settings)
}

func (MemoryRegistration) Configure(
	_ context.Context,
	raw json.RawMessage,
	services Services,
	config *builtin.Config,
) error {
	normalized, err := (MemoryRegistration{}).Normalize("core.memory", raw)
	if err != nil {
		return err
	}
	var settings MemorySettings
	if err := json.Unmarshal(normalized, &settings); err != nil {
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
