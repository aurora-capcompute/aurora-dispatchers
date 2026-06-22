package registry

import (
	"aurora-dispatchers/builtin"
	"aurora-dispatchers/internet"
	"aurora-dispatchers/llm"
	"aurora-dispatchers/mcp"
	"bytes"
	"capcompute/dispatcher"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

type Services struct {
	LLM        llm.Client
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

type Registry struct {
	registrations []Registration
}

func New(registrations ...Registration) *Registry {
	return &Registry{registrations: append([]Registration(nil), registrations...)}
}

func Default() *Registry {
	return New(InternetRegistration{}, MCPRegistration{})
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
	config := builtin.Config{LLM: services.LLM}
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
