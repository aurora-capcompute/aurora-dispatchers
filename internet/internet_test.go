package internet_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aurora-capcompute/aurora-dispatchers/internet"
)

func TestAllowedGETSucceeds(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	client := internet.NewClient(mustPolicy(t, "GET:"+server.URL))
	response, err := client.Do(context.Background(), internet.Request{Method: "GET", URL: server.URL})
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	if response.Status != http.StatusOK || response.Body != "ok" {
		t.Fatalf("response = %+v", response)
	}
	if response.Headers["Content-Type"] != "text/plain" {
		t.Fatalf("headers = %+v, want the Content-Type surfaced", response.Headers)
	}
}

// A grant that allowlists POST can write: the request body reaches the server
// and the response comes back.
func TestAllowedPOSTSendsBody(t *testing.T) {
	var seen struct {
		method      string
		body        string
		contentType string
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.method = r.Method
		seen.contentType = r.Header.Get("Content-Type")
		body, _ := io.ReadAll(r.Body)
		seen.body = string(body)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"created":true}`))
	}))
	defer server.Close()

	client := internet.NewClient(mustPolicy(t, "POST:"+server.URL))
	response, err := client.Do(context.Background(), internet.Request{
		Method:  "POST",
		URL:     server.URL,
		Headers: map[string]string{"Content-Type": "application/json"},
		Body:    `{"hello":"world"}`,
	})
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	if seen.method != "POST" || seen.body != `{"hello":"world"}` || seen.contentType != "application/json" {
		t.Fatalf("server saw %+v", seen)
	}
	if response.Status != http.StatusCreated || response.Body != `{"created":true}` {
		t.Fatalf("response = %+v", response)
	}
}

func TestDisallowedDomainFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("request should not reach disallowed server")
	}))
	defer server.Close()

	client := internet.NewClient(mustPolicy(t, "GET:https://example.com"))
	_, err := client.Do(context.Background(), internet.Request{Method: "GET", URL: server.URL})
	if err == nil || !strings.Contains(err.Error(), "not allowlisted") {
		t.Fatalf("error = %v, want not-allowlisted", err)
	}
}

// A method outside the grant's allowlist is refused even when the host is
// allowed.
func TestDisallowedMethodFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("request should not reach server")
	}))
	defer server.Close()

	client := internet.NewClient(mustPolicy(t, "GET:"+server.URL))
	_, err := client.Do(context.Background(), internet.Request{Method: "DELETE", URL: server.URL})
	if err == nil || !strings.Contains(err.Error(), "not allowlisted") {
		t.Fatalf("error = %v, want not-allowlisted", err)
	}
}

// The method wildcard "*" lets a grant permit every method against a host.
func TestMethodWildcardAllowsAnyMethod(t *testing.T) {
	policy := mustPolicy(t, "*:https://api.example.com")
	for _, method := range []string{"GET", "POST", "PUT", "PATCH", "DELETE"} {
		if err := policy.Allows(method, "https://api.example.com/x"); err != nil {
			t.Fatalf("method %s: %v", method, err)
		}
	}
	if err := policy.Allows("GET", "https://other.example.com"); err == nil {
		t.Fatal("wildcard method must still pin the host")
	}
}

func TestHostWildcardPinsMethod(t *testing.T) {
	policy := mustPolicy(t, "GET:*")
	for _, target := range []string{"https://example.com/path", "http://localhost:8080/value"} {
		if err := policy.Allows(http.MethodGet, target); err != nil {
			t.Fatalf("allow %s: %v", target, err)
		}
	}
	if err := policy.Allows(http.MethodPost, "https://example.com"); err == nil {
		t.Fatal("host wildcard must still pin the method")
	}
}

func TestNonHTTPSchemeFails(t *testing.T) {
	client := internet.NewClient(mustPolicy(t, "GET:https://example.com"))
	_, err := client.Do(context.Background(), internet.Request{Method: "GET", URL: "file:///tmp/data.txt"})
	if err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("error = %v, want scheme-not-allowed", err)
	}
}

func TestRedirectToDisallowedDomainFails(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("redirect target should not be reached")
	}))
	defer target.Close()

	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer source.Close()

	client := internet.NewClient(mustPolicy(t, "GET:"+source.URL))
	_, err := client.Do(context.Background(), internet.Request{Method: "GET", URL: source.URL})
	if err == nil || !strings.Contains(err.Error(), "not allowlisted") {
		t.Fatalf("error = %v, want not-allowlisted", err)
	}
}

func TestResponseBodyIsByteLimited(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("abcdef"))
	}))
	defer server.Close()

	client := internet.NewClient(mustPolicy(t, "GET:"+server.URL))
	client.MaxBytes = 3
	response, err := client.Do(context.Background(), internet.Request{Method: "GET", URL: server.URL})
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	if response.Body != "abc" {
		t.Fatalf("body = %q, want abc", response.Body)
	}
}

func TestRequestBodyIsByteLimited(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("oversized request should not be sent")
	}))
	defer server.Close()

	client := internet.NewClient(mustPolicy(t, "POST:"+server.URL))
	client.MaxRequestBytes = 4
	_, err := client.Do(context.Background(), internet.Request{Method: "POST", URL: server.URL, Body: "toolong"})
	if err == nil || !strings.Contains(err.Error(), "request body exceeds") {
		t.Fatalf("error = %v, want request-body-exceeds", err)
	}
}

func mustPolicy(t *testing.T, raw string) internet.Policy {
	t.Helper()
	policy, err := internet.ParseAllowlist(raw)
	if err != nil {
		t.Fatalf("parse policy: %v", err)
	}
	return policy
}
