package openaillm

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

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
		requiredField:   op.requiredField,
		defaultModel:    normalized.DefaultModel,
		models:          newModelPolicy(normalized.AllowedModels),
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

func TestModelPolicyRejectsBeforeProviderCall(t *testing.T) {
	client := &recordingClient{}
	handler := operationHandler(t, client, "embeddings", Settings{DefaultModel: "model-a", AllowedModels: []string{"model-a"}})
	outcome, err := handler.DispatchCall(context.Background(), openaiCall("embeddings", `"model":"model-b","input":"hello"`))
	if err != nil {
		t.Fatalf("dispatch embeddings: %v", err)
	}
	if outcome.Status() != sys.StatusFailed || len(client.calls) != 0 {
		t.Fatalf("outcome = %s, calls = %v; want a failure before any provider call", outcome.Status(), client.calls)
	}
}

func TestStreamingIsRejected(t *testing.T) {
	handler := operationHandler(t, &recordingClient{}, "responses", Settings{DefaultModel: "model-a"})
	outcome, err := handler.DispatchCall(context.Background(), openaiCall("responses", `"input":"hello","stream":true`))
	if err != nil {
		t.Fatalf("dispatch responses: %v", err)
	}
	if outcome.Status() != sys.StatusFailed {
		t.Fatalf("outcome = %s, want failed", outcome.Status())
	}
}
