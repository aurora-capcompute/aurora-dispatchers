package openaillm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/aurora-capcompute/aurora-capcompute/capability"
	"github.com/aurora-capcompute/aurora-dispatchers/registry"
)

// SyscallType is the manifest `syscall` for an OpenAI-compatible cognition
// grant, and the name of the single capability it publishes: its operations
// (chat, responses, embeddings, models) are cases of one discriminated ADT,
// selected by the `operation` field in the call args.
const SyscallType = "core.openaiApi"

// openaiOperations are the cases a core.openaiApi grant may enable, each with
// the field schema its args carry (minus the `operation` discriminator, which
// registry.OperationBranch injects) and a one-line description.
var openaiOperations = map[string]struct {
	schema      json.RawMessage
	description string
}{
	"chat":       {schemas["chat"], "chat: create a Chat Completions response"},
	"responses":  {schemas["responses"], "responses: create a Responses API response"},
	"embeddings": {schemas["embeddings"], "embeddings: create embeddings"},
	"models":     {schemas["models"], "models: list provider models"},
}

// Operations returns the operation names this driver exposes, sorted.
func Operations() []string {
	names := make([]string, 0, len(openaiOperations))
	for name := range openaiOperations {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// grantConfig is a core.openaiApi grant's driver configuration: the operations
// it grants (each an ADT case with its flow policy) plus the connection settings
// (base_url, api_key, default_model, …), which are flattened alongside.
type grantConfig struct {
	Capabilities json.RawMessage `json:"capabilities,omitempty"`
	Settings
}

type Registration struct{}

func (Registration) Matches(syscallType string) bool { return syscallType == SyscallType }

// Configure publishes the single core.openaiApi capability — a oneOf over the
// granted operations — and the handler that serves them. The grant is kept off
// the discoverable menu via the manifest `hidden` flag (the agent calls the LLM
// itself; the model never sees it).
func (Registration) Configure(_ context.Context, raw json.RawMessage, services registry.Services) (capability.Family, error) {
	config, grants, err := parseGrantConfig(raw)
	if err != nil {
		return capability.Family{}, err
	}
	normalized, err := normalizeSettings(config.Settings)
	if err != nil {
		return capability.Family{}, err
	}
	// Resolve the credential host-side (activation): a missing referenced secret
	// fails the build here, never silently at call time. The value is never
	// persisted — Normalize keeps only the reference.
	apiKey, err := config.Settings.APIKey.Resolve(services.Secrets)
	if err != nil {
		return capability.Family{}, fmt.Errorf("core.openaiApi api_key: %w", err)
	}
	normalized.apiKey = apiKey
	// One handler backs every operation of this grant. The table refuses a
	// second Add for the same syscall, so the old find-or-create scan — which
	// existed to share a handler across repeated grants — has nothing to find:
	// the manifest already rejects a duplicate syscall.
	client, err := NewClient(normalized)
	if err != nil {
		client = failedClient{err: err}
	}
	handler := NewHandler(client)
	handler.connection = connectionFor(normalized)

	entries := make([]capability.Entry, 0, len(grants))
	branches := make([]json.RawMessage, 0, len(grants))
	descriptions := make([]string, 0, len(grants))
	for _, grant := range grants {
		handler.AddOperation(grant.Operation, normalized, grant)
		branch, err := registry.OperationBranch(grant.Operation, openaiOperations[grant.Operation].schema)
		if err != nil {
			return capability.Family{}, err
		}
		entries = append(entries, capability.Entry{
			Key:           capability.Key{Syscall: SyscallType, Operation: grant.Operation},
			Discriminator: "operation",
			Description:   openaiOperations[grant.Operation].description,
			Input:         branch,
			Labels:        grant.Labels,
			// A provider call sends the prompt off-host — egress — so floor the
			// reserved secret class into the sink guard on top of any declared
			// taints. Enforcement is the runtime monitor's, above the journal;
			// declaring it here is the whole of this driver's part.
			Forbid:  registry.WithEgressFloor(grant.Taints),
			Handler: handler,
		})
		branches = append(branches, branch)
		descriptions = append(descriptions, openaiOperations[grant.Operation].description)
	}
	return capability.Family{Entries: entries,
		Description: fmt.Sprintf("OpenAI-compatible cognition. Provider: %s; %s. Choose an operation:\n- %s.",
			normalized.BaseURL, modelScope(normalized), strings.Join(descriptions, "\n- ")),
		Input: registry.OneOfSchema(branches),
	}, nil
}

func modelScope(settings normalizedSettings) string {
	if len(settings.AllowedModels) > 0 {
		return "models: " + strings.Join(settings.AllowedModels, ", ")
	}
	return "all models"
}

// parseGrantConfig validates and canonicalizes a core.openaiApi grant's config:
// it requires at least one operation from the known set with no duplicates and
// normalizes each operation's flow policy. Connection settings are validated by
// normalizeSettings at build time.
func parseGrantConfig(raw json.RawMessage) (grantConfig, []registry.OperationGrant, error) {
	var config grantConfig
	if len(raw) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&config); err != nil {
			return grantConfig{}, nil, err
		}
	}
	grants, err := registry.DecodeOperationGrants(config.Capabilities)
	if err != nil {
		return grantConfig{}, nil, err
	}
	if len(grants) == 0 {
		return grantConfig{}, nil, fmt.Errorf("capabilities must grant at least one operation (%s)", strings.Join(Operations(), ", "))
	}
	seen := make(map[string]struct{}, len(grants))
	for i := range grants {
		operation := strings.TrimSpace(grants[i].Operation)
		if _, ok := openaiOperations[operation]; !ok {
			return grantConfig{}, nil, fmt.Errorf("unknown openai operation %q (want %s)", grants[i].Operation, strings.Join(Operations(), ", "))
		}
		if _, dup := seen[operation]; dup {
			return grantConfig{}, nil, fmt.Errorf("duplicate openai operation %q", operation)
		}
		seen[operation] = struct{}{}
		grants[i].Operation = operation
		if grants[i].FlowPolicy, err = grants[i].FlowPolicy.Normalized(); err != nil {
			return grantConfig{}, nil, fmt.Errorf("operation %q: %w", operation, err)
		}
	}
	sort.Slice(grants, func(i, j int) bool { return grants[i].Operation < grants[j].Operation })
	return config, grants, nil
}

func connectionFor(settings normalizedSettings) connectionSettings {
	maxRetries := 0
	maxRetriesSet := settings.MaxRetries != nil
	if maxRetriesSet {
		maxRetries = *settings.MaxRetries
	}
	headers := make([]string, 0, len(settings.Headers))
	for header, value := range settings.Headers {
		headers = append(headers, header+"="+value)
	}
	sort.Strings(headers)
	return connectionSettings{
		baseURL:        settings.BaseURL,
		apiKey:         settings.apiKey,
		apiKeyOptional: settings.APIKeyOptional,
		organization:   settings.Organization,
		project:        settings.Project,
		timeout:        settings.timeout.String(),
		maxRetries:     maxRetries,
		maxRetriesSet:  maxRetriesSet,
		insecureHTTP:   settings.AllowInsecureHTTP,
		headers:        strings.Join(headers, "\n"),
	}
}

type failedClient struct{ err error }

func (c failedClient) Chat(context.Context, json.RawMessage) (json.RawMessage, error) {
	return nil, c.err
}
func (c failedClient) Responses(context.Context, json.RawMessage) (json.RawMessage, error) {
	return nil, c.err
}
func (c failedClient) Embeddings(context.Context, json.RawMessage) (json.RawMessage, error) {
	return nil, c.err
}
func (c failedClient) Models(context.Context) (json.RawMessage, error) {
	return nil, c.err
}

var schemas = map[string]json.RawMessage{
	"chat":       json.RawMessage(`{"type":"object","properties":{"model":{"type":"string"},"messages":{"type":"array","items":{"type":"object","properties":{"role":{"type":"string"},"content":{}},"required":["role","content"],"additionalProperties":true}},"temperature":{"type":"number","minimum":0,"maximum":2},"top_p":{"type":"number","minimum":0,"maximum":1},"max_tokens":{"type":"integer","minimum":1},"max_completion_tokens":{"type":"integer","minimum":1},"response_format":{"type":"object"},"tools":{"type":"array"},"tool_choice":{},"stream":{"const":false}},"required":["messages"],"additionalProperties":true}`),
	"responses":  json.RawMessage(`{"type":"object","properties":{"model":{"type":"string"},"input":{},"instructions":{"type":"string"},"max_output_tokens":{"type":"integer","minimum":1},"temperature":{"type":"number","minimum":0,"maximum":2},"tools":{"type":"array"},"stream":{"const":false}},"required":["input"],"additionalProperties":true}`),
	"embeddings": json.RawMessage(`{"type":"object","properties":{"model":{"type":"string"},"input":{"oneOf":[{"type":"string"},{"type":"array","items":{"type":"string"}}]},"dimensions":{"type":"integer","minimum":1},"encoding_format":{"enum":["float","base64"]}},"required":["input"],"additionalProperties":true}`),
	"models":     json.RawMessage(`{"type":"object","additionalProperties":true}`),
}
