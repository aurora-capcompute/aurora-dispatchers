package openaillm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aurora-capcompute/aurora-dispatchers/builtin"
	"github.com/aurora-capcompute/capcompute/sys"
)

var _ builtin.Handler = (*Handler)(nil)

type capabilityConfig struct {
	defaultModel    string
	modelPolicy     modelPolicy
	maxRequestBytes int
	requireApproval bool
}

type connectionSettings struct {
	baseURL        string
	apiKey         string
	apiKeyOptional bool
	organization   string
	project        string
	timeout        string
	maxRetries     int
	maxRetriesSet  bool
	insecureHTTP   bool
	headers        string
}

type Handler struct {
	client       Client
	capabilities map[string]capabilityConfig
	connection   connectionSettings
}

func NewHandler(client Client) *Handler {
	return &Handler{client: client, capabilities: make(map[string]capabilityConfig)}
}

func (h *Handler) AddCapability(name string, settings normalizedSettings) {
	h.capabilities[name] = capabilityConfig{
		defaultModel:    settings.DefaultModel,
		modelPolicy:     newModelPolicy(settings.AllowedModels),
		maxRequestBytes: settings.MaxRequestBytes,
		requireApproval: requiresApproval(name, settings.Settings),
	}
}

func (h *Handler) Handles(name string) bool {
	_, ok := h.capabilities[name]
	return ok
}

func (h *Handler) DispatchCall(ctx context.Context, call sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	capability, ok := h.capabilities[call.Name]
	if !ok {
		return sys.FailCode(sys.ErrnoNotFound, "unknown OpenAI-compatible call: "+call.Name), nil
	}
	if len(call.Args) > capability.maxRequestBytes {
		return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("request exceeds %d bytes", capability.maxRequestBytes)), nil
	}

	switch call.Name {
	case "openai.chat":
		return h.dispatchModelRequest(ctx, call, capability, "messages", h.client.Chat, auth)
	case "openai.responses":
		return h.dispatchModelRequest(ctx, call, capability, "input", h.client.Responses, auth)
	case "openai.embeddings":
		return h.dispatchModelRequest(ctx, call, capability, "input", h.client.Embeddings, auth)
	case "openai.models.list":
		return h.dispatchModels(ctx, capability, auth)
	default:
		return sys.FailCode(sys.ErrnoNotFound, "unsupported OpenAI-compatible operation: "+call.Name), nil
	}
}

func (h *Handler) dispatchModelRequest(
	ctx context.Context,
	call sys.Syscall,
	capability capabilityConfig,
	requiredField string,
	invoke func(context.Context, json.RawMessage) (json.RawMessage, error),
	auth sys.Authorization,
) (sys.SyscallResult, error) {
	payload, outcome := preparePayload(call, capability, requiredField)
	if outcome != nil {
		return *outcome, nil
	}
	model, _ := payload["model"].(string)
	if outcome := approval(auth, capability, fmt.Sprintf("%s using model %s", call.Name, model)); outcome != nil {
		return *outcome, nil
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return sys.SyscallResult{}, err
	}
	response, err := invoke(ctx, body)
	return providerResult(ctx, response, err)
}

func (h *Handler) dispatchModels(ctx context.Context, capability capabilityConfig, auth sys.Authorization) (sys.SyscallResult, error) {
	if outcome := approval(auth, capability, "openai.models.list"); outcome != nil {
		return *outcome, nil
	}
	response, err := h.client.Models(ctx)
	return providerResult(ctx, response, err)
}

func preparePayload(
	call sys.Syscall,
	capability capabilityConfig,
	requiredField string,
) (map[string]any, *sys.SyscallResult) {
	decoder := json.NewDecoder(bytes.NewReader(call.Args))
	decoder.UseNumber()
	var payload map[string]any
	if err := decoder.Decode(&payload); err != nil {
		outcome := sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("decode %s: %v", call.Name, err))
		return nil, &outcome
	}
	if payload == nil {
		outcome := sys.FailCode(sys.ErrnoInvalidArgs, "request must be a JSON object")
		return nil, &outcome
	}
	if stream, ok := payload["stream"].(bool); ok && stream {
		outcome := sys.FailCode(sys.ErrnoInvalidArgs, "streaming requests are not supported by syscall results")
		return nil, &outcome
	}
	if _, ok := payload[requiredField]; !ok {
		outcome := sys.FailCode(sys.ErrnoInvalidArgs, requiredField+" is required")
		return nil, &outcome
	}

	model, _ := payload["model"].(string)
	model = strings.TrimSpace(model)
	if model == "" {
		model = capability.defaultModel
	}
	if model == "" {
		outcome := sys.FailCode(sys.ErrnoInvalidArgs, "model is required when no default_model is configured")
		return nil, &outcome
	}
	if err := capability.modelPolicy.check(model); err != nil {
		outcome := sys.FailCode(sys.ErrnoDenied, err.Error())
		return nil, &outcome
	}
	payload["model"] = model
	return payload, nil
}

func approval(auth sys.Authorization, capability capabilityConfig, summary string) *sys.SyscallResult {
	if !capability.requireApproval {
		return nil
	}
	if auth.Decision == sys.Approved {
		return nil
	}
	outcome := sys.Yield("Approve: " + strings.TrimSpace(summary))
	return &outcome
}

func providerResult(ctx context.Context, response json.RawMessage, err error) (sys.SyscallResult, error) {
	if err != nil {
		if ctx.Err() != nil {
			return sys.SyscallResult{}, ctx.Err()
		}
		return sys.FailCode(sys.ErrnoTransient, err.Error()), nil
	}
	if !json.Valid(response) {
		return sys.FailCode(sys.ErrnoTransient, "provider returned invalid JSON"), nil
	}
	return sys.Result(response), nil
}
