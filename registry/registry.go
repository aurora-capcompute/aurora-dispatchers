package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aurora-capcompute/aurora-dispatchers/builtin"
	"github.com/aurora-capcompute/aurora-dispatchers/internet"
	"github.com/aurora-capcompute/aurora-dispatchers/mcp"
	"github.com/aurora-capcompute/aurora-dispatchers/timer"
	"github.com/aurora-capcompute/capcompute/dispatcher"
	"strings"
	"time"
)

type Services struct {
	MCPServers map[string]mcp.ServerConfig
}

type Registration interface {
	Matches(string) bool
	Normalize(string, json.RawMessage) (json.RawMessage, error)
	Configure(context.Context, string, json.RawMessage, Services, *builtin.Config) error
}

type SubsetValidator interface {
	IsSubset(name string, parent, child json.RawMessage) error
}

// CognitionRegistration is an optional interface for registrations that drive
// the agent's reasoning rather than exposing an operational tool. Capabilities
// matched by a CognitionRegistration are kept dispatchable by the runtime but
// hidden from the brain's operational tool list via the manifest Hidden flag.
type CognitionRegistration interface {
	IsCognition() bool
}

func (r *Registry) IsCognition(name string) bool {
	for _, registration := range r.registrations {
		if registration.Matches(name) {
			if cr, ok := registration.(CognitionRegistration); ok {
				return cr.IsCognition()
			}
		}
	}
	return false
}

type Registry struct {
	registrations []Registration
}

func New(registrations ...Registration) *Registry {
	return &Registry{registrations: append([]Registration(nil), registrations...)}
}

func Default() *Registry {
	return New(InternetRegistration{}, MCPRegistration{}, TimerRegistration{})
}

func (r *Registry) Normalize(name string, settings json.RawMessage) (json.RawMessage, error) {
	for _, registration := range r.registrations {
		if registration.Matches(name) {
			return registration.Normalize(name, settings)
		}
	}
	return nil, fmt.Errorf("unsupported dispatcher %q", name)
}

func (r *Registry) IsSubset(name string, parent, child json.RawMessage) error {
	for _, registration := range r.registrations {
		if registration.Matches(name) {
			if validator, ok := registration.(SubsetValidator); ok {
				return validator.IsSubset(name, parent, child)
			}
			if !bytes.Equal(parent, child) {
				return fmt.Errorf("capability %q does not support subset validation; settings must be identical", name)
			}
			return nil
		}
	}
	return fmt.Errorf("unsupported dispatcher %q", name)
}

func (r *Registry) Build(ctx context.Context, entries []Entry, services Services) (builtin.Config, error) {
	var config builtin.Config
	for _, entry := range entries {
		var selected Registration
		for _, registration := range r.registrations {
			if registration.Matches(entry.Name) {
				selected = registration
				break
			}
		}
		if selected == nil {
			return builtin.Config{}, fmt.Errorf("unsupported dispatcher %q", entry.Name)
		}
		if err := selected.Configure(ctx, entry.Name, entry.Settings, services, &config); err != nil {
			return builtin.Config{}, err
		}
	}
	return config, nil
}

type Entry struct {
	Name     string
	Settings json.RawMessage
}

type InternetSettings struct {
	Allow            []string `json:"allow"`
	TimeoutMS        int64    `json:"timeout_ms,omitempty"`
	MaxResponseBytes int64    `json:"max_response_bytes,omitempty"`
	RequireApproval  bool     `json:"require_approval,omitempty"`
}

type InternetRegistration struct{}

func (InternetRegistration) Matches(name string) bool { return name == "internet.read" }

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
	if len(settings.Allow) == 0 {
		return nil, fmt.Errorf("allow must contain at least one origin or *")
	}
	for i, origin := range settings.Allow {
		origin = strings.TrimSpace(origin)
		if origin == "" {
			return nil, fmt.Errorf("allow entry %d is empty", i)
		}
		settings.Allow[i] = origin
	}
	if settings.TimeoutMS <= 0 {
		return nil, fmt.Errorf("timeout_ms must be positive")
	}
	if settings.MaxResponseBytes <= 0 {
		return nil, fmt.Errorf("max_response_bytes must be positive")
	}
	return json.Marshal(settings)
}

func (InternetRegistration) IsSubset(_ string, parent, child json.RawMessage) error {
	var parentSettings, childSettings InternetSettings
	if err := json.Unmarshal(parent, &parentSettings); err != nil {
		return fmt.Errorf("decode parent settings: %w", err)
	}
	if err := json.Unmarshal(child, &childSettings); err != nil {
		return fmt.Errorf("decode child settings: %w", err)
	}
	if len(parentSettings.Allow) > 0 {
		allowed := make(map[string]struct{}, len(parentSettings.Allow))
		for _, origin := range parentSettings.Allow {
			allowed[origin] = struct{}{}
		}
		hasWildcard := false
		for _, origin := range parentSettings.Allow {
			if origin == "*" {
				hasWildcard = true
				break
			}
		}
		if !hasWildcard {
			for _, origin := range childSettings.Allow {
				if _, ok := allowed[origin]; !ok {
					return fmt.Errorf("child origin %q is not in parent's allowed origins", origin)
				}
			}
		}
	}
	return nil
}

func (InternetRegistration) Configure(
	_ context.Context,
	_ string,
	raw json.RawMessage,
	_ Services,
	config *builtin.Config,
) error {
	normalized, err := (InternetRegistration{}).Normalize("internet.read", raw)
	if err != nil {
		return err
	}
	var settings InternetSettings
	if err := json.Unmarshal(normalized, &settings); err != nil {
		return err
	}
	entries := make([]string, 0, len(settings.Allow))
	for _, origin := range settings.Allow {
		entries = append(entries, "GET:"+origin)
	}
	policy, err := internet.ParseAllowlist(strings.Join(entries, ","))
	if err != nil {
		return err
	}
	config.Internet = internet.NewConfiguredClient(
		policy,
		time.Duration(settings.TimeoutMS)*time.Millisecond,
		settings.MaxResponseBytes,
	)
	config.InternetRequireApproval = settings.RequireApproval
	config.Capabilities = append(config.Capabilities, dispatcher.Capability{
		Name:        "internet.read",
		Description: "Read textual content with HTTP GET. Allowed origins: " + strings.Join(settings.Allow, ", "),
		InputSchema: json.RawMessage(`{"type":"object","properties":{"method":{"type":"string","const":"GET"},"url":{"type":"string","format":"uri"}},"required":["method","url"],"additionalProperties":false}`),
	})
	return nil
}

type MCPSettings struct {
	ServerID string   `json:"server_id,omitempty"`
	Tools    []string `json:"tools,omitempty"`
}

type MCPRegistration struct{}

func (MCPRegistration) Matches(name string) bool { return strings.HasPrefix(name, "mcp.") }

func (MCPRegistration) Normalize(name string, raw json.RawMessage) (json.RawMessage, error) {
	var settings MCPSettings
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &settings); err != nil {
			return nil, err
		}
	}
	if strings.TrimSpace(settings.ServerID) == "" {
		settings.ServerID = strings.TrimPrefix(name, "mcp.")
	}
	settings.ServerID = strings.TrimSpace(settings.ServerID)
	if settings.ServerID == "" {
		return nil, errors.New("server_id is required")
	}
	return json.Marshal(settings)
}

func (MCPRegistration) IsSubset(_ string, parent, child json.RawMessage) error {
	var parentSettings, childSettings MCPSettings
	if err := json.Unmarshal(parent, &parentSettings); err != nil {
		return fmt.Errorf("decode parent settings: %w", err)
	}
	if err := json.Unmarshal(child, &childSettings); err != nil {
		return fmt.Errorf("decode child settings: %w", err)
	}
	if parentSettings.ServerID != childSettings.ServerID {
		return fmt.Errorf("child server_id %q differs from parent %q", childSettings.ServerID, parentSettings.ServerID)
	}
	if len(parentSettings.Tools) > 0 && len(childSettings.Tools) > 0 {
		allowed := make(map[string]struct{}, len(parentSettings.Tools))
		for _, tool := range parentSettings.Tools {
			allowed[tool] = struct{}{}
		}
		for _, tool := range childSettings.Tools {
			if _, ok := allowed[tool]; !ok {
				return fmt.Errorf("child tool %q is not in parent's allowed tools", tool)
			}
		}
	}
	return nil
}

func (MCPRegistration) Configure(
	ctx context.Context,
	name string,
	raw json.RawMessage,
	services Services,
	config *builtin.Config,
) error {
	normalized, err := (MCPRegistration{}).Normalize(name, raw)
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

type AuroraLogRegistration struct{}

func (AuroraLogRegistration) Matches(name string) bool { return name == "aurora.log" }

func (AuroraLogRegistration) Normalize(_ string, raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 {
		return json.RawMessage(`{}`), nil
	}
	return raw, nil
}

func (AuroraLogRegistration) Configure(
	_ context.Context,
	_ string,
	_ json.RawMessage,
	_ Services,
	_ *builtin.Config,
) error {
	return nil
}

type TimerSettings struct {
	MaxDurationMS int64 `json:"max_duration_ms,omitempty"`
}

type TimerRegistration struct{}

func (TimerRegistration) Matches(name string) bool { return name == timer.Capability }

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
	_ string,
	raw json.RawMessage,
	_ Services,
	config *builtin.Config,
) error {
	normalized, err := (TimerRegistration{}).Normalize("timer.set", raw)
	if err != nil {
		return err
	}
	var settings TimerSettings
	if err := json.Unmarshal(normalized, &settings); err != nil {
		return err
	}
	maxDuration := time.Duration(settings.MaxDurationMS) * time.Millisecond
	config.Handlers = append(config.Handlers, timer.Handler{MaxDuration: maxDuration})
	config.Capabilities = append(config.Capabilities, dispatcher.Capability{
		Name: timer.Capability,
		Description: fmt.Sprintf(
			"Set a relative timer and be replayed when it fires. The run pauses until the duration elapses, then continues. Maximum %s.",
			maxDuration,
		),
		InputSchema: json.RawMessage(`{"type":"object","properties":{"duration_seconds":{"type":"integer","minimum":1},"label":{"type":"string"}},"required":["duration_seconds"],"additionalProperties":false}`),
	})
	return nil
}
