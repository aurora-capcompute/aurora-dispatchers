package openaillm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aurora-capcompute/aurora-dispatchers/registry"
)

// Regression: the SSRF guard must run AFTER DNS resolution (on the resolved IP),
// not on the unresolved hostname. Guarding the hostname rejected every hostname
// base_url as "not an IP", breaking the driver out of the box. Here a
// non-loopback base_url arms the guard, and a request via a hostname (localhost)
// that resolves to the loopback test server must be blocked as "non-public"
// (post-resolution) — never with the pre-fix "did not resolve to an IP".
func TestGuardedTransportGuardsResolvedIPNotHostname(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()

	client := &http.Client{Transport: guardedTransport("https://api.example.com/v1", 5*time.Second)}
	target := strings.Replace(server.URL, "127.0.0.1", "localhost", 1)
	_, err := client.Get(target)
	if err == nil {
		t.Fatal("expected the loopback dial to be blocked by the SSRF guard")
	}
	if strings.Contains(err.Error(), "did not resolve to an IP") {
		t.Fatalf("REGRESSION: guard ran on the unresolved hostname (the pre-fix bug): %v", err)
	}
	if !strings.Contains(err.Error(), "non-public") {
		t.Fatalf("expected a post-resolution non-public block, got: %v", err)
	}
}

// A loopback base_url (local dev) opts out of the guard, so the dial to the
// loopback provider succeeds — the driver must work against a local endpoint.
func TestGuardedTransportAllowsLoopbackBaseURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := &http.Client{Transport: guardedTransport(server.URL, 5*time.Second)}
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("a loopback base_url must permit the dial: %v", err)
	}
	_ = resp.Body.Close()
}

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
		APIKey:            registry.LiteralSecret("test-key"),
		Headers:           map[string]string{"X-Gateway-Tenant": "tenant-a"},
	})
	if err != nil {
		t.Fatalf("settings: %v", err)
	}
	settings.apiKey = "test-key" // resolved host-side by Configure in production
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
