package openaillm

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/aurora-capcompute/aurora-dispatchers/registry"
	"github.com/aurora-capcompute/capcompute/sys"
)

type mockClient struct {
	chatCalls       int
	responsesCalls  int
	embeddingsCalls int
	modelCalls      int
	lastBody        json.RawMessage
}

func (m *mockClient) Chat(_ context.Context, body json.RawMessage) (json.RawMessage, error) {
	m.chatCalls++
	m.lastBody = append([]byte(nil), body...)
	return json.RawMessage(`{"id":"chat-1","choices":[]}`), nil
}
func (m *mockClient) Responses(_ context.Context, body json.RawMessage) (json.RawMessage, error) {
	m.responsesCalls++
	m.lastBody = append([]byte(nil), body...)
	return json.RawMessage(`{"id":"resp-1","output":[]}`), nil
}
func (m *mockClient) Embeddings(_ context.Context, body json.RawMessage) (json.RawMessage, error) {
	m.embeddingsCalls++
	m.lastBody = append([]byte(nil), body...)
	return json.RawMessage(`{"data":[]}`), nil
}
func (m *mockClient) Models(context.Context) (json.RawMessage, error) {
	m.modelCalls++
	return json.RawMessage(`{"data":[{"id":"model-a"}]}`), nil
}

// operationHandler builds a handler granting one operation, its approval
// requirement supplied by the grant entry (nil = the driver's default).
func operationHandler(t *testing.T, client Client, operation string, settings Settings, requireApproval *bool) *Handler {
	t.Helper()
	normalized, err := normalizeSettings(settings)
	if err != nil {
		t.Fatalf("settings: %v", err)
	}
	handler := NewHandler(client)
	handler.AddOperation(operation, normalized, registry.OperationGrant{Operation: operation, RequireApproval: requireApproval})
	return handler
}

func openaiCall(operation, fields string) sys.Syscall {
	args := `{"operation":"` + operation + `"}`
	if fields != "" {
		args = `{"operation":"` + operation + `",` + fields + `}`
	}
	return sys.Syscall{Name: SyscallType, Args: json.RawMessage(args)}
}

func TestChatYieldsByDefaultAndRunsAfterApproval(t *testing.T) {
	client := &mockClient{}
	handler := operationHandler(t, client, "chat", Settings{
		DefaultModel:  "model-a",
		AllowedModels: []string{"model-a"},
	}, nil)
	call := openaiCall("chat", `"messages":[{"role":"user","content":"hello"}]`)

	outcome, err := handler.DispatchCall(context.Background(), call, sys.Authorization{})
	if err != nil {
		t.Fatalf("dispatch chat: %v", err)
	}
	if outcome.Status() != sys.StatusYield {
		t.Fatalf("outcome = %s, want yield", outcome.Status())
	}
	if client.chatCalls != 0 {
		t.Fatal("provider called before approval")
	}

	outcome, err = handler.DispatchCall(context.Background(), call, sys.Authorization{Decision: sys.Approved})
	if err != nil {
		t.Fatalf("dispatch approved chat: %v", err)
	}
	if outcome.Status() != sys.StatusResult {
		t.Fatalf("outcome = %s, want result", outcome.Status())
	}
	var body map[string]any
	if err := json.Unmarshal(client.lastBody, &body); err != nil {
		t.Fatalf("decode provider body: %v", err)
	}
	if body["model"] != "model-a" {
		t.Fatalf("model = %v, want model-a", body["model"])
	}
	// The `operation` discriminator must not be forwarded to the provider.
	if _, leaked := body["operation"]; leaked {
		t.Fatal("operation discriminator leaked into the provider request")
	}
}

func TestModelPolicyRejectsBeforeProviderCall(t *testing.T) {
	client := &mockClient{}
	approval := false
	handler := operationHandler(t, client, "embeddings", Settings{
		DefaultModel:  "model-a",
		AllowedModels: []string{"model-a"},
	}, &approval)

	outcome, err := handler.DispatchCall(context.Background(), openaiCall("embeddings", `"model":"model-b","input":"hello"`), sys.Authorization{})
	if err != nil {
		t.Fatalf("dispatch embeddings: %v", err)
	}
	if outcome.Status() != sys.StatusFailed {
		t.Fatalf("outcome = %s, want failed", outcome.Status())
	}
	if client.embeddingsCalls != 0 {
		t.Fatal("provider called for disallowed model")
	}
}

func TestModelsListDoesNotRequireApprovalByDefault(t *testing.T) {
	client := &mockClient{}
	handler := operationHandler(t, client, "models", Settings{}, nil)

	outcome, err := handler.DispatchCall(context.Background(), openaiCall("models", ""), sys.Authorization{})
	if err != nil {
		t.Fatalf("dispatch models: %v", err)
	}
	if outcome.Status() != sys.StatusResult {
		t.Fatalf("outcome = %s, want result", outcome.Status())
	}
	if client.modelCalls != 1 {
		t.Fatalf("model calls = %d, want 1", client.modelCalls)
	}
}

func TestStreamingIsRejected(t *testing.T) {
	client := &mockClient{}
	approval := false
	handler := operationHandler(t, client, "responses", Settings{DefaultModel: "model-a"}, &approval)

	outcome, err := handler.DispatchCall(context.Background(), openaiCall("responses", `"input":"hello","stream":true`), sys.Authorization{})
	if err != nil {
		t.Fatalf("dispatch responses: %v", err)
	}
	if outcome.Status() != sys.StatusFailed {
		t.Fatalf("outcome = %s, want failed", outcome.Status())
	}
}

// An ungranted operation is denied — the grant selects which ADT cases exist.
func TestUngrantedOperationDenied(t *testing.T) {
	handler := operationHandler(t, &mockClient{}, "chat", Settings{DefaultModel: "model-a"}, nil)
	outcome, err := handler.DispatchCall(context.Background(), openaiCall("embeddings", `"input":"x"`), sys.Authorization{})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if outcome.Status() != sys.StatusFailed || outcome.Errno() != sys.ErrnoDenied {
		t.Fatalf("ungranted op = %v/%v, want failed/denied", outcome.Status(), outcome.Errno())
	}
}
