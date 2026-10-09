package openaillm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"

	"github.com/aurora-capcompute/aurora-capcompute/capability"
	"github.com/aurora-capcompute/aurora-dispatchers/registry"
	"github.com/aurora-capcompute/capcompute/sys"
)

// SyscallType is the manifest `syscall` for an OpenAI-compatible cognition
// grant, and the name of the single capability it publishes: its operations
// (chat, responses, embeddings, models) are cases of one discriminated ADT,
// selected by the `operation` field in the call args.
const SyscallType = "core.openaiApi"

// openaiOperations are the cases a core.openaiApi grant may enable, each with
// the field schema its args carry (minus the `operation` discriminator, which
// registry.OperationBranch injects), a one-line description, the provider path,
// and the HTTP method. The schemas refuse streaming, and the Validator holds
// every call to them before it reaches the handler.
var openaiOperations = map[string]struct {
	schema      json.RawMessage
	description string
	path        string
	method      string
}{
	"chat": {
		schema:      json.RawMessage(`{"type":"object","properties":{"model":{"type":"string"},"messages":{"type":"array","items":{"type":"object","properties":{"role":{"type":"string"},"content":{}},"required":["role","content"],"additionalProperties":true}},"temperature":{"type":"number","minimum":0,"maximum":2},"top_p":{"type":"number","minimum":0,"maximum":1},"max_tokens":{"type":"integer","minimum":1},"max_completion_tokens":{"type":"integer","minimum":1},"response_format":{"type":"object"},"tools":{"type":"array"},"tool_choice":{},"stream":{"const":false}},"required":["messages"],"additionalProperties":true}`),
		description: "chat: create a Chat Completions response",
		path:        "chat/completions",
		method:      http.MethodPost,
	},
	"responses": {
		schema:      json.RawMessage(`{"type":"object","properties":{"model":{"type":"string"},"input":{},"instructions":{"type":"string"},"max_output_tokens":{"type":"integer","minimum":1},"temperature":{"type":"number","minimum":0,"maximum":2},"tools":{"type":"array"},"stream":{"const":false}},"required":["input"],"additionalProperties":true}`),
		description: "responses: create a Responses API response",
		path:        "responses",
		method:      http.MethodPost,
	},
	"embeddings": {
		schema:      json.RawMessage(`{"type":"object","properties":{"model":{"type":"string"},"input":{"oneOf":[{"type":"string"},{"type":"array","items":{"type":"string"}}]},"dimensions":{"type":"integer","minimum":1},"encoding_format":{"enum":["float","base64"]}},"required":["input"],"additionalProperties":true}`),
		description: "embeddings: create embeddings",
		path:        "embeddings",
		method:      http.MethodPost,
	},
	"models": {
		schema:      json.RawMessage(`{"type":"object","additionalProperties":true}`),
		description: "models: list provider models",
		path:        "models",
		method:      http.MethodGet,
	},
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
// granted operations — and one handler per operation. The grant is kept off
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
	client, err := newProvider(normalized)
	if err != nil {
		return capability.Family{}, fmt.Errorf("core.openaiApi: %w", err)
	}

	entries := make([]capability.Entry, 0, len(grants))
	descriptions := make([]string, 0, len(grants))
	for _, grant := range grants {
		op := openaiOperations[grant.Operation]
		schema, err := allowModels(op.schema, normalized.AllowedModels)
		if err != nil {
			return capability.Family{}, err
		}
		branch, err := registry.OperationBranch(grant.Operation, schema)
		if err != nil {
			return capability.Family{}, err
		}
		entry := capability.Entry{
			Key:           capability.Key{Syscall: SyscallType, Operation: grant.Operation},
			Discriminator: "operation",
			Description:   op.description,
			Input:         branch,
			Labels:        grant.Labels,
			// A provider call sends the prompt off-host — egress — so floor the
			// reserved secret class into the sink guard on top of any declared
			// taints. Enforcement is the runtime monitor's, above the journal;
			// declaring it here is the whole of this driver's part.
			Forbid:          registry.WithEgressFloor(grant.Taints),
			RequireApproval: grant.RequireApproval != nil && *grant.RequireApproval,
			Handler: operation{
				client:          client,
				path:            op.path,
				method:          op.method,
				defaultModel:    normalized.DefaultModel,
				maxRequestBytes: normalized.MaxRequestBytes,
			},
		}
		if grant.Operation != "models" {
			entry.Prompt = modelPrompt(normalized.DefaultModel)
		}
		entries = append(entries, entry)
		descriptions = append(descriptions, op.description)
	}
	return capability.Family{Entries: entries,
		Description: fmt.Sprintf("OpenAI-compatible cognition. Provider: %s; %s. Choose an operation:\n- %s.",
			normalized.BaseURL, modelScope(normalized), strings.Join(descriptions, "\n- ")),
	}, nil
}

// allowModels narrows an operation's model field to the allowed models, so the
// Validator refuses any other model before a human is asked to approve the
// call. An empty list allows any model.
func allowModels(schema json.RawMessage, allowed []string) (json.RawMessage, error) {
	if len(allowed) == 0 {
		return schema, nil
	}
	var document map[string]any
	if err := json.Unmarshal(schema, &document); err != nil {
		return nil, err
	}
	properties, _ := document["properties"].(map[string]any)
	if _, ok := properties["model"]; !ok {
		return schema, nil
	}
	properties["model"] = map[string]any{"type": "string", "enum": allowed}
	return json.Marshal(document)
}

// modelPrompt shows the human approving a model call which model it runs on:
// the call's own, else the grant's default.
func modelPrompt(defaultModel string) func(sys.Syscall) string {
	return func(call sys.Syscall) string {
		// The Validator admitted these arguments against the operation's schema.
		var args struct {
			Model string `json:"model"`
		}
		_ = json.Unmarshal(call.Args, &args)
		model := strings.TrimSpace(args.Model)
		if model == "" {
			model = defaultModel
		}
		return "model: " + model
	}
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
	grants, err := registry.ParseOperationGrants(config.Capabilities, "openai", slices.Sorted(maps.Keys(openaiOperations)))
	if err != nil {
		return grantConfig{}, nil, err
	}
	return config, grants, nil
}
