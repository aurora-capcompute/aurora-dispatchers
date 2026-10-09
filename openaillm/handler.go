package openaillm

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/aurora-capcompute/capcompute/sys"
)

// operation serves one granted case of core.openaiApi (chat, responses,
// embeddings or models). The grant table routed the call here, and the entry's
// approval and flow policy held before it arrived. The Validator held the args
// to the operation's schema: an object with the required fields, no streaming,
// and an allowed model.
type operation struct {
	client          Client
	path            string
	method          string
	defaultModel    string
	maxRequestBytes int
}

func (o operation) DispatchCall(ctx context.Context, call sys.Syscall) (sys.SyscallResult, error) {
	if o.method == http.MethodGet {
		response, err := o.client.Do(ctx, http.MethodGet, o.path, nil)
		return providerResult(ctx, response, err)
	}
	if len(call.Args) > o.maxRequestBytes {
		return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("request exceeds %d bytes", o.maxRequestBytes)), nil
	}
	decoder := json.NewDecoder(bytes.NewReader(call.Args))
	decoder.UseNumber()
	var payload map[string]any
	if err := decoder.Decode(&payload); err != nil {
		return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("decode %s: %v", o.path, err)), nil
	}
	// The `operation` discriminator selects the case. It is not part of the
	// provider request body.
	delete(payload, "operation")
	model, _ := payload["model"].(string)
	model = cmp.Or(strings.TrimSpace(model), o.defaultModel)
	if model == "" {
		return sys.FailCode(sys.ErrnoInvalidArgs, "model is required when no default_model is configured"), nil
	}
	payload["model"] = model
	body, err := json.Marshal(payload)
	if err != nil {
		return sys.SyscallResult{}, err
	}
	response, err := o.client.Do(ctx, http.MethodPost, o.path, body)
	return providerResult(ctx, response, err)
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
