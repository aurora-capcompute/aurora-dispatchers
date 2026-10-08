package openaillm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/aurora-capcompute/capcompute/sys"
)

// operation serves one granted case of core.openaiApi (chat, responses,
// embeddings or models). The grant table routed the call here, and the entry's
// approval and flow policy held before it arrived.
type operation struct {
	client Client
	path   string
	// requiredField is the field a request must carry ("messages", "input");
	// empty for models, which is a GET with no body.
	requiredField   string
	defaultModel    string
	models          modelPolicy
	maxRequestBytes int
}

func (o operation) DispatchCall(ctx context.Context, call sys.Syscall) (sys.SyscallResult, error) {
	if o.requiredField == "" {
		response, err := o.client.Do(ctx, http.MethodGet, o.path, nil)
		return providerResult(ctx, response, err)
	}
	if len(call.Args) > o.maxRequestBytes {
		return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("request exceeds %d bytes", o.maxRequestBytes)), nil
	}
	payload, outcome := o.payload(call)
	if outcome != nil {
		return *outcome, nil
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return sys.SyscallResult{}, err
	}
	response, err := o.client.Do(ctx, http.MethodPost, o.path, body)
	return providerResult(ctx, response, err)
}

// payload is the provider request body: the call's arguments without the
// `operation` discriminator, with the default model filled in and checked
// against the allowed models.
func (o operation) payload(call sys.Syscall) (map[string]any, *sys.SyscallResult) {
	decoder := json.NewDecoder(bytes.NewReader(call.Args))
	decoder.UseNumber()
	var payload map[string]any
	if err := decoder.Decode(&payload); err != nil {
		outcome := sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("decode %s: %v", o.path, err))
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
	if _, ok := payload[o.requiredField]; !ok {
		outcome := sys.FailCode(sys.ErrnoInvalidArgs, o.requiredField+" is required")
		return nil, &outcome
	}

	model, _ := payload["model"].(string)
	model = strings.TrimSpace(model)
	if model == "" {
		model = o.defaultModel
	}
	if model == "" {
		outcome := sys.FailCode(sys.ErrnoInvalidArgs, "model is required when no default_model is configured")
		return nil, &outcome
	}
	if err := o.models.check(model); err != nil {
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
