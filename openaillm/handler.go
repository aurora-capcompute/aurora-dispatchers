package openaillm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aurora-capcompute/capcompute/sys"
)

type capabilityConfig struct {
	defaultModel    string
	modelPolicy     modelPolicy
	maxRequestBytes int
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

// Handler serves one core.openaiApi grant: a single capability whose operations
// (chat, responses, embeddings, models) are cases selected by the `operation`
// discriminator in the call args.
type Handler struct {
	client     Client
	operations map[string]capabilityConfig
	connection connectionSettings
}

func NewHandler(client Client) *Handler {
	return &Handler{client: client, operations: make(map[string]capabilityConfig)}
}

// AddOperation records one granted operation's model defaults and limits. Its
// approval and flow policy are the grant table entry's, enforced before the
// call reaches this handler.
func (h *Handler) AddOperation(operation string, settings normalizedSettings) {
	h.operations[operation] = capabilityConfig{
		defaultModel:    settings.DefaultModel,
		modelPolicy:     newModelPolicy(settings.AllowedModels),
		maxRequestBytes: settings.MaxRequestBytes,
	}
}

func (h *Handler) Handles(name string) bool { return name == SyscallType }

func (h *Handler) DispatchCall(ctx context.Context, call sys.Syscall, _ sys.Authorization) (sys.SyscallResult, error) {
	operation, err := peekOperation(call.Args)
	if err != nil {
		return sys.FailCode(sys.ErrnoInvalidArgs, err.Error()), nil
	}
	capability, ok := h.operations[operation]
	if !ok {
		return sys.FailCode(sys.ErrnoDenied, "openai operation is not granted: "+operation), nil
	}
	if len(call.Args) > capability.maxRequestBytes {
		return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("request exceeds %d bytes", capability.maxRequestBytes)), nil
	}
	var result sys.SyscallResult
	switch operation {
	case "chat":
		result, err = h.dispatchModelRequest(ctx, call, capability, operation, "messages", h.client.Chat)
	case "responses":
		result, err = h.dispatchModelRequest(ctx, call, capability, operation, "input", h.client.Responses)
	case "embeddings":
		result, err = h.dispatchModelRequest(ctx, call, capability, operation, "input", h.client.Embeddings)
	case "models":
		result, err = h.dispatchModels(ctx)
	default:
		return sys.FailCode(sys.ErrnoNotFound, "unsupported openai operation: "+operation), nil
	}
	if err != nil || result.Status() != sys.StatusResult {
		return result, err
	}
	return result, nil
}

// peekOperation reads the ADT discriminator from an openai call's args.
func peekOperation(args json.RawMessage) (string, error) {
	var envelope struct {
		Operation string `json:"operation"`
	}
	if err := json.Unmarshal(args, &envelope); err != nil {
		return "", fmt.Errorf("decode operation: %v", err)
	}
	if envelope.Operation == "" {
		return "", fmt.Errorf("operation is required")
	}
	return envelope.Operation, nil
}

func (h *Handler) dispatchModelRequest(
	ctx context.Context,
	call sys.Syscall,
	capability capabilityConfig,
	operation string,
	requiredField string,
	invoke func(context.Context, json.RawMessage) (json.RawMessage, error),
) (sys.SyscallResult, error) {
	payload, outcome := preparePayload(call, capability, operation, requiredField)
	if outcome != nil {
		return *outcome, nil
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return sys.SyscallResult{}, err
	}
	response, err := invoke(ctx, body)
	return providerResult(ctx, response, err)
}

func (h *Handler) dispatchModels(ctx context.Context) (sys.SyscallResult, error) {
	response, err := h.client.Models(ctx)
	return providerResult(ctx, response, err)
}

func preparePayload(
	call sys.Syscall,
	capability capabilityConfig,
	operation string,
	requiredField string,
) (map[string]any, *sys.SyscallResult) {
	decoder := json.NewDecoder(bytes.NewReader(call.Args))
	decoder.UseNumber()
	var payload map[string]any
	if err := decoder.Decode(&payload); err != nil {
		outcome := sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("decode %s: %v", operation, err))
		return nil, &outcome
	}
	if payload == nil {
		outcome := sys.FailCode(sys.ErrnoInvalidArgs, "request must be a JSON object")
		return nil, &outcome
	}
	// The `operation` discriminator selects the case; it is not part of the
	// provider request body.
	delete(payload, "operation")
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

// providerResult classifies the outcome of a provider call the driver actually
// made. Nothing here labels: the monitor's stamp sits above this driver and
// labels every outcome it returns, failures included — which is what keeps a
// failed call's error text from being an untainted channel a forbidding sink
// would accept. The context-cancellation branch returns an error rather than a
// result, so no journaled outcome is produced and nothing is stamped.
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
