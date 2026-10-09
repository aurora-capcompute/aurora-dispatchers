package openaillm

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/aurora-capcompute/aurora-capcompute/capability"
	"github.com/aurora-capcompute/aurora-capcompute/monitor"
	"github.com/aurora-capcompute/capcompute/sys"
)

// recordingClient records each provider call and answers with a fixed body,
// or with err.
type recordingClient struct {
	calls    []string
	lastBody json.RawMessage
	err      error
}

func (c *recordingClient) Do(_ context.Context, method, path string, body json.RawMessage) (json.RawMessage, error) {
	c.calls = append(c.calls, method+" "+path)
	c.lastBody = append([]byte(nil), body...)
	if c.err != nil {
		return nil, c.err
	}
	return json.RawMessage(`{"id":"x"}`), nil
}

// operationHandler builds the handler a grant of one operation gets.
func operationHandler(t *testing.T, client Client, name string, settings Settings) operation {
	t.Helper()
	normalized, err := normalizeSettings(settings)
	if err != nil {
		t.Fatalf("settings: %v", err)
	}
	op := openaiOperations[name]
	return operation{
		client:          client,
		path:            op.path,
		method:          op.method,
		defaultModel:    normalized.DefaultModel,
		maxRequestBytes: normalized.MaxRequestBytes,
	}
}

func openaiCall(operation, fields string) sys.Syscall {
	args := `{"operation":"` + operation + `"}`
	if fields != "" {
		args = `{"operation":"` + operation + `",` + fields + `}`
	}
	return sys.Syscall{Name: SyscallType, Args: json.RawMessage(args)}
}

var errProvider = errors.New("provider unavailable")

// A failed provider call is a transient failure, and the handler labels
// nothing: the monitor's stamp above it labels every outcome, failures
// included (monitor.TestStampLabelsFailuresToo).
func TestProviderErrorIsTransient(t *testing.T) {
	handler := operationHandler(t, &recordingClient{err: errProvider}, "chat", Settings{DefaultModel: "model-a"})
	outcome, err := handler.DispatchCall(context.Background(), openaiCall("chat", `"messages":[{"role":"user","content":"hi"}]`))
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if outcome.Status() != sys.StatusFailed || outcome.Errno() != sys.ErrnoTransient {
		t.Fatalf("outcome = %s/%v, want failed/transient", outcome.Status(), outcome.Errno())
	}
	if len(outcome.Labels()) != 0 {
		t.Fatalf("handler labelled %v; labelling belongs to the monitor above it", outcome.Labels())
	}
}

// The handler forwards the request to its path with the default model filled
// in and without the `operation` discriminator.
func TestChatForwardsTheRequest(t *testing.T) {
	client := &recordingClient{}
	handler := operationHandler(t, client, "chat", Settings{DefaultModel: "model-a", AllowedModels: []string{"model-a"}})
	outcome, err := handler.DispatchCall(context.Background(), openaiCall("chat", `"messages":[{"role":"user","content":"hello"}]`))
	if err != nil || outcome.Status() != sys.StatusResult {
		t.Fatalf("dispatch = %v, %v; want a result", outcome.Status(), err)
	}
	if len(client.calls) != 1 || client.calls[0] != "POST chat/completions" {
		t.Fatalf("calls = %v", client.calls)
	}
	var body map[string]any
	if err := json.Unmarshal(client.lastBody, &body); err != nil {
		t.Fatalf("decode provider body: %v", err)
	}
	if body["model"] != "model-a" {
		t.Fatalf("model = %v, want model-a", body["model"])
	}
	if _, leaked := body["operation"]; leaked {
		t.Fatal("operation discriminator leaked into the provider request")
	}
}

func TestModelsIsAGet(t *testing.T) {
	client := &recordingClient{}
	handler := operationHandler(t, client, "models", Settings{})
	if outcome, err := handler.DispatchCall(context.Background(), openaiCall("models", "")); err != nil || outcome.Status() != sys.StatusResult {
		t.Fatalf("dispatch = %v, %v; want a result", outcome.Status(), err)
	}
	if len(client.calls) != 1 || client.calls[0] != "GET models" {
		t.Fatalf("calls = %v", client.calls)
	}
}

// The operation schemas refuse a model the grant does not allow, and a
// streaming request, before any provider call.
func TestSchemaRefusesBeforeProviderCall(t *testing.T) {
	raw := json.RawMessage(`{"api_key":{"secret":"OPENAI_KEY"},"default_model":"model-a","allowed_models":["model-a"],"capabilities":[{"operation":"embeddings"},{"operation":"responses"}]}`)
	family, err := (Registration{}).Configure(context.Background(), raw, keyed)
	if err != nil {
		t.Fatalf("configure: %v", err)
	}
	table := capability.NewTable()
	if err := table.Add(family); err != nil {
		t.Fatalf("add: %v", err)
	}
	validated := monitor.NewValidator(table, sys.Dispatcher[string](capability.NewDispatcher[string](table)))
	for _, call := range []sys.Syscall{
		openaiCall("embeddings", `"model":"model-b","input":"hello"`),
		openaiCall("responses", `"input":"hello","stream":true`),
	} {
		outcome, err := validated.Dispatch(context.Background(), "p1", call, sys.Authorization{})
		if err != nil {
			t.Fatalf("dispatch %s: %v", call.Args, err)
		}
		if outcome.Status() != sys.StatusFailed || outcome.Errno() != sys.ErrnoInvalidArgs {
			t.Fatalf("%s = %s/%v, want failed/invalid_args", call.Args, outcome.Status(), outcome.Errno())
		}
	}
}
