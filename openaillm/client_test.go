package openaillm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSDKClientUsesCompatibleEndpointsAndHeaders(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
		}
		if r.Header.Get("X-Gateway-Tenant") != "tenant-a" {
			t.Errorf("tenant header = %q", r.Header.Get("X-Gateway-Tenant"))
		}
		if r.Header.Get("X-Leaked") != "" {
			t.Errorf("ambient OPENAI_CUSTOM_HEADERS leaked into request")
		}
		switch r.URL.Path {
		case "/v1/chat/completions":
			body, _ := io.ReadAll(r.Body)
			if !json.Valid(body) {
				t.Errorf("invalid request JSON: %s", body)
			}
			_, _ = w.Write([]byte(`{"id":"chat-1","choices":[]}`))
		case "/v1/models":
			_, _ = w.Write([]byte(`{"data":[{"id":"model-a"}]}`))
		default:
			http.Error(w, "unexpected path", http.StatusNotFound)
		}
	}))
	defer server.Close()

	t.Setenv("OPENAI_CUSTOM_HEADERS", "X-Leaked: yes")
	settings, err := normalizeSettings(Settings{
		BaseURL:           server.URL + "/v1",
		AllowInsecureHTTP: true,
		APIKey:            "test-key",
		Headers:           map[string]string{"X-Gateway-Tenant": "tenant-a"},
	})
	if err != nil {
		t.Fatalf("settings: %v", err)
	}
	client, err := NewClient(settings)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	if _, err := client.Chat(context.Background(), json.RawMessage(`{"model":"model-a","messages":[]}`)); err != nil {
		t.Fatalf("chat: %v", err)
	}
	if _, err := client.Models(context.Background()); err != nil {
		t.Fatalf("models: %v", err)
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want 2", requests)
	}
}

func TestAPIKeyRequiredUnlessOptional(t *testing.T) {
	settings, err := normalizeSettings(Settings{})
	if err != nil {
		t.Fatalf("settings: %v", err)
	}
	if _, err := NewClient(settings); err == nil {
		t.Fatal("expected missing API key error")
	}
}
