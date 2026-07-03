package openaillm

import (
	"context"
	"encoding/json"
	"testing"

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

func TestChatYieldsByDefaultAndRunsAfterApproval(t *testing.T) {
	client := &mockClient{}
	settings, err := normalizeSettings(Settings{
		DefaultModel:  "model-a",
		AllowedModels: []string{"model-a"},
	})
	if err != nil {
		t.Fatalf("settings: %v", err)
	}
	handler := NewHandler(client)
	handler.AddCapability("openai.chat", settings)
	call := sys.Syscall{
		Name: "openai.chat",
		Args: json.RawMessage(`{"messages":[{"role":"user","content":"hello"}]}`),
	}

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
}

func TestModelPolicyRejectsBeforeProviderCall(t *testing.T) {
	client := &mockClient{}
	approval := false
	settings, err := normalizeSettings(Settings{
		DefaultModel:    "model-a",
		AllowedModels:   []string{"model-a"},
		RequireApproval: &approval,
	})
	if err != nil {
		t.Fatalf("settings: %v", err)
	}
	handler := NewHandler(client)
	handler.AddCapability("openai.embeddings", settings)

	outcome, err := handler.DispatchCall(context.Background(), sys.Syscall{
		Name: "openai.embeddings",
		Args: json.RawMessage(`{"model":"model-b","input":"hello"}`),
	}, sys.Authorization{})
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
	settings, err := normalizeSettings(Settings{})
	if err != nil {
		t.Fatalf("settings: %v", err)
	}
	handler := NewHandler(client)
	handler.AddCapability("openai.models.list", settings)

	outcome, err := handler.DispatchCall(context.Background(), sys.Syscall{
		Name: "openai.models.list",
		Args: json.RawMessage(`{}`),
	}, sys.Authorization{})
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
	settings, err := normalizeSettings(Settings{
		DefaultModel:    "model-a",
		RequireApproval: &approval,
	})
	if err != nil {
		t.Fatalf("settings: %v", err)
	}
	handler := NewHandler(client)
	handler.AddCapability("openai.responses", settings)

	outcome, err := handler.DispatchCall(context.Background(), sys.Syscall{
		Name: "openai.responses",
		Args: json.RawMessage(`{"input":"hello","stream":true}`),
	}, sys.Authorization{})
	if err != nil {
		t.Fatalf("dispatch responses: %v", err)
	}
	if outcome.Status() != sys.StatusFailed {
		t.Fatalf("outcome = %s, want failed", outcome.Status())
	}
}
