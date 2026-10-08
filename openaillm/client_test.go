package openaillm

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aurora-capcompute/aurora-dispatchers/registry"
)

func testProvider(t *testing.T, settings Settings, apiKey string) provider {
	t.Helper()
	normalized, err := normalizeSettings(settings)
	if err != nil {
		t.Fatalf("settings: %v", err)
	}
	normalized.apiKey = apiKey // resolved host-side by Configure in production
	p, err := newProvider(normalized)
	if err != nil {
		t.Fatalf("new provider: %v", err)
	}
	return p
}

// The provider sends to the endpoint's paths, with the key, the organization
// and project, and the grant's own headers.
func TestProviderSendsToTheEndpointWithItsHeaders(t *testing.T) {
	var seen []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.Path)
		for header, want := range map[string]string{
			"Authorization":       "Bearer test-key",
			"OpenAI-Organization": "org-1",
			"X-Gateway-Tenant":    "tenant-a",
			"Content-Type":        "application/json",
		} {
			if got := r.Header.Get(header); got != want {
				t.Errorf("%s = %q, want %q", header, got, want)
			}
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	p := testProvider(t, Settings{
		BaseURL:           server.URL + "/v1",
		AllowInsecureHTTP: true,
		APIKey:            registry.SecretRef("OPENAI_KEY"),
		Organization:      "org-1",
		Headers:           map[string]string{"X-Gateway-Tenant": "tenant-a"},
	}, "test-key")
	if _, err := p.Do(context.Background(), http.MethodPost, "chat/completions", []byte(`{"model":"m","messages":[]}`)); err != nil {
		t.Fatalf("chat: %v", err)
	}
	if _, err := p.Do(context.Background(), http.MethodGet, "models", nil); err != nil {
		t.Fatalf("models: %v", err)
	}
	if strings.Join(seen, ", ") != "POST /v1/chat/completions, GET /v1/models" {
		t.Fatalf("requests = %v", seen)
	}
}

// A 5xx is tried again, up to max_retries; a 4xx is not, and its error quotes
// the provider's body (where a context-length message lives).
func TestProviderRetriesTransientFailures(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		body, _ := io.ReadAll(r.Body)
		switch {
		case strings.Contains(string(body), "bad"):
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"maximum context length exceeded"}`))
		case requests == 1:
			w.WriteHeader(http.StatusServiceUnavailable)
		default:
			_, _ = w.Write([]byte(`{"ok":true}`))
		}
	}))
	defer server.Close()

	retries := 1
	p := testProvider(t, Settings{BaseURL: server.URL, AllowInsecureHTTP: true, APIKeyOptional: true, MaxRetries: &retries}, "")
	if _, err := p.Do(context.Background(), http.MethodPost, "chat/completions", []byte(`{}`)); err != nil || requests != 2 {
		t.Fatalf("Do = %v after %d requests, want success on the retry", err, requests)
	}
	requests = 0
	_, err := p.Do(context.Background(), http.MethodPost, "chat/completions", []byte(`{"bad":true}`))
	if err == nil || requests != 1 || !strings.Contains(err.Error(), "maximum context length") {
		t.Fatalf("Do = %v after %d requests, want one try and the provider's message", err, requests)
	}
}

// A base_url that is not loopback is held to the dial guard, so an internal
// address never receives the key.
func TestProviderRefusesAPrivateAddress(t *testing.T) {
	none := 0
	p := testProvider(t, Settings{BaseURL: "https://10.255.255.1/v1", MaxRetries: &none}, "test-key")
	_, err := p.Do(context.Background(), http.MethodGet, "models", nil)
	if err == nil || !strings.Contains(err.Error(), "non-public") {
		t.Fatalf("Do = %v, want the dial guard's refusal", err)
	}
}

func TestAPIKeyRequiredUnlessOptional(t *testing.T) {
	settings, err := normalizeSettings(Settings{})
	if err != nil {
		t.Fatalf("settings: %v", err)
	}
	if _, err := newProvider(settings); err == nil {
		t.Fatal("expected missing API key error")
	}
}
